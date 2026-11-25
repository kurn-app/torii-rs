//! `torii_sessions`.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use torii_core::{
    Error, Session, UserId, error::StorageError, repositories::SessionRepository,
    session::SessionToken,
};

use crate::{Db, Row, millis, text_or_null};

const COLUMNS: &str = "token_hash, user_id, user_agent, ip_address, expires_at, created_at, \
                       updated_at";

/// [`SessionRepository`] over `torii_sessions`. A session token is stored only as its hash.
#[derive(Clone)]
pub struct DoSessionRepository {
    db: Db,
}

impl DoSessionRepository {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }

    fn find(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        let query = format!("SELECT {COLUMNS} FROM torii_sessions WHERE token_hash = ?");
        let rows = self.db.rows(&query, vec![token.token_hash().into()])?;
        rows.first()
            .map(|row| session(row, Some(token.clone())))
            .transpose()
    }
}

fn session(
    values: &[worker::SqlStorageValue],
    token: Option<SessionToken>,
) -> Result<Session, Error> {
    let row = Row::new("torii_sessions", values);
    Ok(Session {
        token,
        token_hash: row.text(0)?,
        user_id: UserId::new(&row.text(1)?),
        user_agent: row.text_or_none(2)?,
        ip_address: row.text_or_none(3)?,
        expires_at: row.time(4)?,
        created_at: row.time(5)?,
        updated_at: row.time(6)?,
    })
}

#[async_trait]
impl SessionRepository for DoSessionRepository {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        let token_hash = match (&session.token, session.token_hash.as_str()) {
            (Some(token), _) => token.token_hash(),
            (None, "") => {
                return Err(StorageError::Database(
                    "a session to store carries neither a token nor its hash".to_owned(),
                )
                .into());
            }
            (None, hash) => hash.to_owned(),
        };
        self.db.exec(
            "INSERT INTO torii_sessions (token_hash, user_id, user_agent, ip_address, expires_at, \
             created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                token_hash.as_str().into(),
                session.user_id.as_str().into(),
                text_or_null(session.user_agent.as_deref()),
                text_or_null(session.ip_address.as_deref()),
                millis(session.expires_at),
                millis(session.created_at),
                millis(session.updated_at),
            ],
        )?;
        Ok(Session {
            token_hash,
            ..session
        })
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        self.find(token)
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<Session>, Error> {
        let query =
            format!("SELECT {COLUMNS} FROM torii_sessions WHERE user_id = ? ORDER BY created_at");
        self.db
            .rows(&query, vec![user_id.as_str().into()])?
            .iter()
            .map(|row| session(row, None))
            .collect()
    }

    async fn delete(&self, token: &SessionToken) -> Result<(), Error> {
        self.db.exec(
            "DELETE FROM torii_sessions WHERE token_hash = ?",
            vec![token.token_hash().into()],
        )
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error> {
        self.db.exec(
            "DELETE FROM torii_sessions WHERE user_id = ?",
            vec![user_id.as_str().into()],
        )
    }

    async fn cleanup_expired(&self) -> Result<(), Error> {
        // `Session::is_expired` is `now > expires_at`, so a session expiring now is still live.
        self.db.exec(
            "DELETE FROM torii_sessions WHERE expires_at < ?",
            vec![millis(Utc::now())],
        )
    }

    async fn refresh(&self, token: &SessionToken, duration: Duration) -> Result<Session, Error> {
        let now = Utc::now();
        let written = self.db.write(
            "UPDATE torii_sessions SET expires_at = ?, updated_at = ? WHERE token_hash = ?",
            vec![
                millis(now + duration),
                millis(now),
                token.token_hash().into(),
            ],
        )?;
        if written == 0 {
            return Err(StorageError::NotFound.into());
        }
        self.find(token)?
            .ok_or_else(|| StorageError::NotFound.into())
    }
}
