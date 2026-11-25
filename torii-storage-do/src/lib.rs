//! A torii storage backend over one Cloudflare Durable Object's SQLite store.
//!
//! [`DoStorage::open`] takes the object's [`SqlStorage`] (`state.storage().sql()`), creates or
//! checks the store's table layout, and hands out the repositories torii's services run over.
//! The Durable Object class, its binding and its migration belong to the Worker that uses it.
//!
//! Every table is prefixed `torii_`, so the object's database can hold the Worker's own tables
//! beside them. At layout [`LAYOUT`]:
//!
//! | table | key |
//! |---|---|
//! | `torii_layout` | one row: the layout |
//! | `torii_users` | `id`; `email` unique |
//! | `torii_sessions` | `token_hash` |
//! | `torii_tokens` | `token_hash` |
//! | `torii_oauth_accounts` | `(provider, subject)` |
//! | `torii_pkce_verifiers` | `csrf_state` |
//! | `torii_failed_logins` | `id`; indexed on `(email, attempted_at)` |
//!
//! - Timestamps are `INTEGER` Unix milliseconds.
//! - Every value is a bound parameter.
//! - Tokens and session tokens are stored only as [`torii_core::crypto::hash_token`].
//!
//! `SqlStorage::exec` is synchronous, and no repository method awaits between its statements, so
//! a torii service call runs inside the object without another request interleaving.

mod brute_force;
mod oauth;
mod session;
mod token;
mod user;

use chrono::{DateTime, Utc};
use torii_core::{
    Error,
    error::StorageError,
    repositories::{
        BruteForceRepositoryProvider, OAuthRepositoryProvider, SessionRepositoryProvider,
        TokenRepositoryProvider, UserRepositoryProvider,
    },
};
use worker::{SqlStorage, SqlStorageValue};

pub use brute_force::DoBruteForceRepository;
pub use oauth::DoOAuthRepository;
pub use session::DoSessionRepository;
pub use token::DoTokenRepository;
pub use user::DoUserRepository;

/// The table layout this build creates and reads.
pub const LAYOUT: i64 = 1;

/// Every statement that creates layout [`LAYOUT`], each idempotent. The layout row is written
/// after all of them, so a creation cut short completes on the next open.
const CREATE: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS torii_layout (version INTEGER)",
    "CREATE TABLE IF NOT EXISTS torii_users (
        id TEXT PRIMARY KEY,
        name TEXT,
        email TEXT NOT NULL UNIQUE,
        email_verified_at INTEGER,
        locked_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS torii_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        user_agent TEXT,
        ip_address TEXT,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS torii_tokens (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        used_at INTEGER,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS torii_oauth_accounts (
        provider TEXT NOT NULL,
        subject TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (provider, subject)
    )",
    "CREATE TABLE IF NOT EXISTS torii_pkce_verifiers (
        csrf_state TEXT PRIMARY KEY,
        pkce_verifier TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS torii_failed_logins (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL,
        ip_address TEXT,
        attempted_at INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS torii_failed_logins_email_attempted_at
        ON torii_failed_logins (email, attempted_at)",
];

/// The torii store over one Durable Object's SQLite database.
///
/// It provides the user, session, token, OAuth and brute-force repositories. It has no password
/// or passkey repository, and so is not torii's aggregate `RepositoryProvider`.
pub struct DoStorage {
    user: DoUserRepository,
    session: DoSessionRepository,
    token: DoTokenRepository,
    oauth: DoOAuthRepository,
    brute_force: DoBruteForceRepository,
}

impl DoStorage {
    /// Opens the store held in `sql`.
    ///
    /// - A store with no `torii_layout` row is empty, whatever other tables the object holds. It
    ///   gets every table and index, and then the layout row.
    /// - A store recording layout [`LAYOUT`] is opened as it is.
    /// - Anything else is refused, naming `torii_layout` and what it holds, and nothing is
    ///   written.
    pub fn open(sql: SqlStorage) -> Result<DoStorage, Error> {
        let db = Db(sql);
        // A no-op on a store that has the table, so the refusal below still writes nothing.
        db.exec(CREATE[0], vec![])?;
        let rows = db.rows("SELECT version FROM torii_layout", vec![])?;
        match layout_reading(&rows)? {
            Layout::Empty => {
                for statement in &CREATE[1..] {
                    db.exec(statement, vec![])?;
                }
                db.exec(
                    "INSERT INTO torii_layout (version) VALUES (?)",
                    vec![LAYOUT.into()],
                )?;
            }
            Layout::Current => {}
        }
        Ok(DoStorage {
            user: DoUserRepository::new(db.clone()),
            session: DoSessionRepository::new(db.clone()),
            token: DoTokenRepository::new(db.clone()),
            oauth: DoOAuthRepository::new(db.clone()),
            brute_force: DoBruteForceRepository::new(db),
        })
    }
}

impl UserRepositoryProvider for DoStorage {
    type UserRepo = DoUserRepository;

    fn user(&self) -> &Self::UserRepo {
        &self.user
    }
}

impl SessionRepositoryProvider for DoStorage {
    type SessionRepo = DoSessionRepository;

    fn session(&self) -> &Self::SessionRepo {
        &self.session
    }
}

impl TokenRepositoryProvider for DoStorage {
    type TokenRepo = DoTokenRepository;

    fn token(&self) -> &Self::TokenRepo {
        &self.token
    }
}

impl OAuthRepositoryProvider for DoStorage {
    type OAuthRepo = DoOAuthRepository;

    fn oauth(&self) -> &Self::OAuthRepo {
        &self.oauth
    }
}

impl BruteForceRepositoryProvider for DoStorage {
    type BruteForceRepo = DoBruteForceRepository;

    fn brute_force(&self) -> &Self::BruteForceRepo {
        &self.brute_force
    }
}

/// What `torii_layout` says the store is.
#[derive(Debug, PartialEq)]
enum Layout {
    /// No row: nothing of torii's has been created yet.
    Empty,
    /// One row, recording [`LAYOUT`].
    Current,
}

/// Reads `torii_layout`'s rows, refusing any layout this build does not read.
fn layout_reading(rows: &[Vec<SqlStorageValue>]) -> Result<Layout, Error> {
    match rows {
        [] => Ok(Layout::Empty),
        [row] if row.as_slice() == [SqlStorageValue::Integer(LAYOUT)] => Ok(Layout::Current),
        [row] => Err(refusal(format!(
            "the store's `torii_layout` records version {}, and this build reads only layout \
             {LAYOUT}; nothing was written",
            row.iter().map(describe).collect::<Vec<_>>().join(", ")
        ))),
        rows => Err(refusal(format!(
            "the store's `torii_layout` holds {} rows ({}), where it holds one; nothing was \
             written",
            rows.len(),
            rows.iter()
                .map(|row| row.iter().map(describe).collect::<Vec<_>>().join(", "))
                .collect::<Vec<_>>()
                .join("; ")
        ))),
    }
}

fn refusal(sentence: String) -> Error {
    Error::Storage(StorageError::Migration(sentence))
}

/// A stored value as a layout refusal names it.
fn describe(value: &SqlStorageValue) -> String {
    match value {
        SqlStorageValue::Null => "NULL".to_owned(),
        SqlStorageValue::Boolean(value) => value.to_string(),
        SqlStorageValue::Integer(value) => value.to_string(),
        SqlStorageValue::Float(value) => value.to_string(),
        SqlStorageValue::String(value) => format!("'{value}'"),
        SqlStorageValue::Blob(bytes) => format!("a {}-byte blob", bytes.len()),
    }
}

/// The object's SQL handle, with its failures mapped to torii's storage error.
#[derive(Clone)]
pub(crate) struct Db(SqlStorage);

impl Db {
    /// Runs `query`, discarding any rows.
    pub(crate) fn exec(&self, query: &str, bindings: Vec<SqlStorageValue>) -> Result<(), Error> {
        self.0
            .exec(query, bindings)
            .map(drop)
            .map_err(|error| failed(query, error))
    }

    /// Runs `query` and answers how many rows it wrote.
    pub(crate) fn write(
        &self,
        query: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<usize, Error> {
        self.0
            .exec(query, bindings)
            .map(|cursor| cursor.rows_written())
            .map_err(|error| failed(query, error))
    }

    /// Every row `query` answers, each as its column values.
    pub(crate) fn rows(
        &self,
        query: &str,
        bindings: Vec<SqlStorageValue>,
    ) -> Result<Vec<Vec<SqlStorageValue>>, Error> {
        self.0
            .exec(query, bindings)
            .map_err(|error| failed(query, error))?
            .raw()
            .collect::<worker::Result<Vec<_>>>()
            .map_err(|error| failed(query, error))
    }
}

fn failed(query: &str, error: worker::Error) -> Error {
    let query = query.split_whitespace().collect::<Vec<_>>().join(" ");
    Error::Storage(StorageError::Database(format!("`{query}` failed: {error}")))
}

/// A timestamp as stored: Unix milliseconds.
pub(crate) fn millis(at: DateTime<Utc>) -> SqlStorageValue {
    SqlStorageValue::Integer(at.timestamp_millis())
}

/// An optional timestamp as stored: Unix milliseconds, or `NULL`.
pub(crate) fn millis_or_null(at: Option<DateTime<Utc>>) -> SqlStorageValue {
    at.map_or(SqlStorageValue::Null, millis)
}

/// An optional string as stored: the text, or `NULL`.
pub(crate) fn text_or_null(value: Option<&str>) -> SqlStorageValue {
    value.map_or(SqlStorageValue::Null, |value| value.into())
}

/// The columns of one row, read by position and named in any failure.
pub(crate) struct Row<'a> {
    table: &'static str,
    values: &'a [SqlStorageValue],
}

impl<'a> Row<'a> {
    pub(crate) fn new(table: &'static str, values: &'a [SqlStorageValue]) -> Self {
        Row { table, values }
    }

    fn value(&self, index: usize) -> Result<&'a SqlStorageValue, Error> {
        self.values
            .get(index)
            .ok_or_else(|| self.unreadable(index, "is missing"))
    }

    pub(crate) fn text(&self, index: usize) -> Result<String, Error> {
        match self.value(index)? {
            SqlStorageValue::String(value) => Ok(value.clone()),
            other => Err(self.unreadable(index, &format!("is {other:?}, not text"))),
        }
    }

    pub(crate) fn text_or_none(&self, index: usize) -> Result<Option<String>, Error> {
        match self.value(index)? {
            SqlStorageValue::Null => Ok(None),
            _ => self.text(index).map(Some),
        }
    }

    pub(crate) fn time(&self, index: usize) -> Result<DateTime<Utc>, Error> {
        match self.value(index)? {
            SqlStorageValue::Integer(ms) => DateTime::from_timestamp_millis(*ms)
                .ok_or_else(|| self.unreadable(index, &format!("is {ms}, out of range"))),
            other => Err(self.unreadable(index, &format!("is {other:?}, not milliseconds"))),
        }
    }

    pub(crate) fn time_or_none(&self, index: usize) -> Result<Option<DateTime<Utc>>, Error> {
        match self.value(index)? {
            SqlStorageValue::Null => Ok(None),
            _ => self.time(index).map(Some),
        }
    }

    fn unreadable(&self, index: usize, what: &str) -> Error {
        Error::Storage(StorageError::Database(format!(
            "a `{}` row's column {index} {what}",
            self.table
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_layout_row_is_an_empty_store() {
        assert_eq!(layout_reading(&[]).unwrap(), Layout::Empty);
    }

    #[test]
    fn the_current_layout_opens() {
        let rows = vec![vec![SqlStorageValue::Integer(LAYOUT)]];
        assert_eq!(layout_reading(&rows).unwrap(), Layout::Current);
    }

    #[test]
    fn another_version_is_refused_by_name() {
        let rows = vec![vec![SqlStorageValue::Integer(2)]];
        let refusal = layout_reading(&rows).unwrap_err().to_string();
        assert!(refusal.contains("torii_layout"), "{refusal}");
        assert!(refusal.contains("version 2"), "{refusal}");
    }

    #[test]
    fn more_than_one_row_is_refused_by_name() {
        let rows = vec![
            vec![SqlStorageValue::Integer(1)],
            vec![SqlStorageValue::Integer(1)],
        ];
        let refusal = layout_reading(&rows).unwrap_err().to_string();
        assert!(refusal.contains("torii_layout"), "{refusal}");
        assert!(refusal.contains("2 rows"), "{refusal}");
    }
}
