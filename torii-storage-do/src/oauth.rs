//! `torii_oauth_accounts` and `torii_pkce_verifiers`.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use torii_core::{
    Error, OAuthAccount, User, UserId, error::AuthError, repositories::OAuthRepository,
};

use crate::{Db, Row, millis, user};

const COLUMNS: &str = "user_id, provider, subject, created_at, updated_at";

/// [`OAuthRepository`] over `torii_oauth_accounts` and `torii_pkce_verifiers`.
///
/// One provider subject maps to one user: `(provider, subject)` is the table's key, and linking
/// a subject that is already linked is refused as [`AuthError::AccountAlreadyLinked`].
#[derive(Clone)]
pub struct DoOAuthRepository {
    db: Db,
}

impl DoOAuthRepository {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }

    fn find_account(&self, provider: &str, subject: &str) -> Result<Option<OAuthAccount>, Error> {
        let query = format!(
            "SELECT {COLUMNS} FROM torii_oauth_accounts WHERE provider = ? AND subject = ?"
        );
        let rows = self
            .db
            .rows(&query, vec![provider.into(), subject.into()])?;
        rows.first().map(|row| account(row)).transpose()
    }

    fn insert(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        if self.find_account(provider, subject)?.is_some() {
            return Err(AuthError::AccountAlreadyLinked.into());
        }
        let now = Utc::now();
        self.db.exec(
            "INSERT INTO torii_oauth_accounts (provider, subject, user_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
            vec![
                provider.into(),
                subject.into(),
                user_id.as_str().into(),
                millis(now),
                millis(now),
            ],
        )?;
        Ok(OAuthAccount {
            user_id: user_id.clone(),
            provider: provider.to_owned(),
            subject: subject.to_owned(),
            created_at: now,
            updated_at: now,
        })
    }
}

fn account(values: &[worker::SqlStorageValue]) -> Result<OAuthAccount, Error> {
    let row = Row::new("torii_oauth_accounts", values);
    Ok(OAuthAccount {
        user_id: UserId::new(&row.text(0)?),
        provider: row.text(1)?,
        subject: row.text(2)?,
        created_at: row.time(3)?,
        updated_at: row.time(4)?,
    })
}

#[async_trait]
impl OAuthRepository for DoOAuthRepository {
    async fn create_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        self.insert(provider, subject, user_id)
    }

    async fn find_user_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        let columns = user::COLUMNS
            .split(", ")
            .map(|column| format!("u.{column}"))
            .collect::<Vec<_>>()
            .join(", ");
        let query = format!(
            "SELECT {columns} FROM torii_oauth_accounts AS a JOIN torii_users AS u \
             ON u.id = a.user_id WHERE a.provider = ? AND a.subject = ?"
        );
        let rows = self
            .db
            .rows(&query, vec![provider.into(), subject.into()])?;
        rows.first().map(|row| user::user(row)).transpose()
    }

    async fn find_account_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        self.find_account(provider, subject)
    }

    async fn find_accounts_by_user_id(&self, user_id: &UserId) -> Result<Vec<OAuthAccount>, Error> {
        let query = format!(
            "SELECT {COLUMNS} FROM torii_oauth_accounts WHERE user_id = ? \
             ORDER BY provider, subject"
        );
        self.db
            .rows(&query, vec![user_id.as_str().into()])?
            .iter()
            .map(|row| account(row))
            .collect()
    }

    async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        self.insert(provider, subject, user_id).map(drop)
    }

    async fn unlink_account(&self, user_id: &UserId, provider: &str) -> Result<(), Error> {
        self.db.exec(
            "DELETE FROM torii_oauth_accounts WHERE user_id = ? AND provider = ?",
            vec![user_id.as_str().into(), provider.into()],
        )
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        self.db.exec(
            "INSERT OR REPLACE INTO torii_pkce_verifiers (csrf_state, pkce_verifier, expires_at) \
             VALUES (?, ?, ?)",
            vec![
                csrf_state.into(),
                pkce_verifier.into(),
                millis(Utc::now() + expires_in),
            ],
        )
    }

    /// The live verifier stored for `csrf_state`. Reading it deletes it, expired or not, so a
    /// verifier is read at most once.
    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        let rows = self.db.rows(
            "SELECT pkce_verifier FROM torii_pkce_verifiers WHERE csrf_state = ? \
             AND expires_at > ?",
            vec![csrf_state.into(), millis(Utc::now())],
        )?;
        self.db.exec(
            "DELETE FROM torii_pkce_verifiers WHERE csrf_state = ?",
            vec![csrf_state.into()],
        )?;
        rows.first()
            .map(|row| Row::new("torii_pkce_verifiers", row).text(0))
            .transpose()
    }

    async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error> {
        self.db.exec(
            "DELETE FROM torii_pkce_verifiers WHERE csrf_state = ?",
            vec![csrf_state.into()],
        )
    }
}
