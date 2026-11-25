//! `torii_tokens`.

use std::str::FromStr;

use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::{TryRngCore, rngs::OsRng};
use torii_core::{
    Error, UserId,
    crypto::hash_token,
    error::StorageError,
    repositories::TokenRepository,
    storage::{SecureToken, TokenPurpose},
};

use crate::{Db, Row, millis};

/// [`TokenRepository`] over `torii_tokens`. A token is stored only as its hash.
#[derive(Clone)]
pub struct DoTokenRepository {
    db: Db,
}

impl DoTokenRepository {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }

    /// The live token `token` names for `purpose`: unexpired and unused.
    fn find_live(&self, token: &str, purpose: TokenPurpose) -> Result<Option<SecureToken>, Error> {
        let rows = self.db.rows(
            "SELECT user_id, token_hash, purpose, used_at, expires_at, created_at, updated_at \
             FROM torii_tokens WHERE token_hash = ? AND purpose = ? AND expires_at > ? \
             AND used_at IS NULL",
            vec![
                hash_token(token).into(),
                purpose.as_str().into(),
                millis(Utc::now()),
            ],
        )?;
        let Some(values) = rows.first() else {
            return Ok(None);
        };
        let row = Row::new("torii_tokens", values);
        let found = SecureToken::from_storage(
            UserId::new(&row.text(0)?),
            row.text(1)?,
            TokenPurpose::from_str(&row.text(2)?)?,
            row.time_or_none(3)?,
            row.time(4)?,
            row.time(5)?,
            row.time(6)?,
        );
        Ok(found.verify(token).then_some(found))
    }
}

/// 32 random bytes, URL-safe base64 with no padding.
fn generate_token() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).map_err(|error| {
        StorageError::Database(format!(
            "the random source gave no bytes for a token: {error}"
        ))
    })?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

#[async_trait]
impl TokenRepository for DoTokenRepository {
    async fn create_token(
        &self,
        user_id: &UserId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        let token = generate_token()?;
        let token_hash = hash_token(&token);
        let now = Utc::now();
        let expires_at = now + expires_in;
        self.db.exec(
            "INSERT INTO torii_tokens (token_hash, user_id, purpose, used_at, expires_at, \
             created_at, updated_at) VALUES (?, ?, ?, NULL, ?, ?, ?)",
            vec![
                token_hash.as_str().into(),
                user_id.as_str().into(),
                purpose.as_str().into(),
                millis(expires_at),
                millis(now),
                millis(now),
            ],
        )?;
        Ok(SecureToken::new(
            user_id.clone(),
            token,
            token_hash,
            purpose,
            None,
            expires_at,
            now,
            now,
        ))
    }

    async fn verify_token(
        &self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        let Some(mut found) = self.find_live(token, purpose)? else {
            return Ok(None);
        };
        let now = Utc::now();
        // Conditional on the row still being unused, so a token verifies once even if another
        // verification of it ran between the read above and this write.
        let written = self.db.write(
            "UPDATE torii_tokens SET used_at = ?, updated_at = ? WHERE token_hash = ? \
             AND used_at IS NULL",
            vec![millis(now), millis(now), found.token_hash.as_str().into()],
        )?;
        if written != 1 {
            return Ok(None);
        }
        found.used_at = Some(now);
        found.updated_at = now;
        Ok(Some(found))
    }

    async fn check_token(&self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
        Ok(self.find_live(token, purpose)?.is_some())
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.db.exec(
            "DELETE FROM torii_tokens WHERE expires_at <= ?",
            vec![millis(Utc::now())],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_32_bytes_of_url_safe_base64_with_no_padding() {
        let token = generate_token().unwrap();
        assert_eq!(token.len(), 43, "{token}");
        assert_eq!(BASE64_URL_SAFE_NO_PAD.decode(&token).unwrap().len(), 32);
        assert_ne!(token, generate_token().unwrap());
    }
}
