//! `torii_failed_logins`, and `torii_users.locked_at`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use torii_core::{
    Error,
    error::StorageError,
    repositories::BruteForceProtectionRepository,
    storage::{AttemptStats, FailedLoginAttempt},
};
use worker::SqlStorageValue;

use crate::{Db, Row, millis, millis_or_null, text_or_null};

/// [`BruteForceProtectionRepository`] over `torii_failed_logins`. An account's lock is the
/// `locked_at` of the `torii_users` row with its email.
#[derive(Clone)]
pub struct DoBruteForceRepository {
    db: Db,
}

impl DoBruteForceRepository {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }
}

#[async_trait]
impl BruteForceProtectionRepository for DoBruteForceRepository {
    async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        let attempted_at = Utc::now();
        let rows = self.db.rows(
            "INSERT INTO torii_failed_logins (email, ip_address, attempted_at) VALUES (?, ?, ?) \
             RETURNING id",
            vec![email.into(), text_or_null(ip_address), millis(attempted_at)],
        )?;
        let id = match rows.first().and_then(|row| row.first()) {
            Some(SqlStorageValue::Integer(id)) => *id,
            other => {
                return Err(StorageError::Database(format!(
                    "a failed login was recorded without an integer id: {other:?}"
                ))
                .into());
            }
        };
        Ok(FailedLoginAttempt {
            id,
            email: email.to_owned(),
            ip_address: ip_address.map(str::to_owned),
            attempted_at,
        })
    }

    async fn get_attempt_stats(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error> {
        let rows = self.db.rows(
            "SELECT COUNT(*), MAX(attempted_at) FROM torii_failed_logins \
             WHERE email = ? AND attempted_at >= ?",
            vec![email.into(), millis(since)],
        )?;
        let values = rows.first().map(Vec::as_slice).unwrap_or_default();
        let count = match values.first() {
            Some(SqlStorageValue::Integer(count)) => u32::try_from(*count).unwrap_or(u32::MAX),
            other => {
                return Err(StorageError::Database(format!(
                    "counting failed logins answered {other:?}"
                ))
                .into());
            }
        };
        Ok(AttemptStats {
            count,
            latest_at: Row::new("torii_failed_logins", values).time_or_none(1)?,
        })
    }

    async fn clear_attempts(&self, email: &str) -> Result<u64, Error> {
        let deleted = self.db.write(
            "DELETE FROM torii_failed_logins WHERE email = ?",
            vec![email.into()],
        )?;
        Ok(deleted as u64)
    }

    /// Deletes the attempts made before `before`, except those of a locked account.
    async fn cleanup_old_attempts(&self, before: DateTime<Utc>) -> Result<u64, Error> {
        let deleted = self.db.write(
            "DELETE FROM torii_failed_logins WHERE attempted_at < ? AND email NOT IN \
             (SELECT email FROM torii_users WHERE locked_at IS NOT NULL)",
            vec![millis(before)],
        )?;
        Ok(deleted as u64)
    }

    async fn set_locked_at(
        &self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        self.db.exec(
            "UPDATE torii_users SET locked_at = ?, updated_at = ? WHERE email = ?",
            vec![millis_or_null(locked_at), millis(Utc::now()), email.into()],
        )
    }

    async fn get_locked_at(&self, email: &str) -> Result<Option<DateTime<Utc>>, Error> {
        let rows = self.db.rows(
            "SELECT locked_at FROM torii_users WHERE email = ?",
            vec![email.into()],
        )?;
        match rows.first() {
            Some(row) => Row::new("torii_users", row).time_or_none(0),
            None => Ok(None),
        }
    }
}
