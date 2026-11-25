//! `torii_users`.

use async_trait::async_trait;
use chrono::Utc;
use torii_core::{
    Error, User, UserId,
    error::{AuthError, StorageError},
    repositories::UserRepository,
    storage::NewUser,
};

use crate::{Db, Row, millis, millis_or_null, text_or_null};

pub(crate) const COLUMNS: &str =
    "id, name, email, email_verified_at, locked_at, created_at, updated_at";

/// [`UserRepository`] over `torii_users`.
#[derive(Clone)]
pub struct DoUserRepository {
    db: Db,
}

impl DoUserRepository {
    pub(crate) fn new(db: Db) -> Self {
        Self { db }
    }

    fn find_one(&self, column: &str, value: &str) -> Result<Option<User>, Error> {
        let query = format!("SELECT {COLUMNS} FROM torii_users WHERE {column} = ?");
        let rows = self.db.rows(&query, vec![value.into()])?;
        rows.first().map(|row| user(row)).transpose()
    }

    fn insert(&self, new_user: NewUser) -> Result<User, Error> {
        if self.find_one("email", &new_user.email)?.is_some() {
            return Err(AuthError::UserAlreadyExists.into());
        }
        let now = Utc::now();
        self.db.exec(
            "INSERT INTO torii_users (id, name, email, email_verified_at, locked_at, created_at, \
             updated_at) VALUES (?, ?, ?, ?, NULL, ?, ?)",
            vec![
                new_user.id.as_str().into(),
                text_or_null(new_user.name.as_deref()),
                new_user.email.as_str().into(),
                millis_or_null(new_user.email_verified_at),
                millis(now),
                millis(now),
            ],
        )?;
        Ok(User {
            id: new_user.id,
            name: new_user.name,
            email: new_user.email,
            email_verified_at: new_user.email_verified_at,
            locked_at: None,
            created_at: now,
            updated_at: now,
        })
    }
}

/// A `torii_users` row, read in [`COLUMNS`] order.
pub(crate) fn user(values: &[worker::SqlStorageValue]) -> Result<User, Error> {
    let row = Row::new("torii_users", values);
    Ok(User {
        id: UserId::new(&row.text(0)?),
        name: row.text_or_none(1)?,
        email: row.text(2)?,
        email_verified_at: row.time_or_none(3)?,
        locked_at: row.time_or_none(4)?,
        created_at: row.time(5)?,
        updated_at: row.time(6)?,
    })
}

#[async_trait]
impl UserRepository for DoUserRepository {
    async fn create(&self, user: NewUser) -> Result<User, Error> {
        self.insert(user)
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        self.find_one("id", id.as_str())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.find_one("email", email)
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        match self.find_one("email", email)? {
            Some(user) => Ok(user),
            None => self.insert(NewUser::new(email.to_owned())),
        }
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        let now = Utc::now();
        let written = self.db.write(
            "UPDATE torii_users SET name = ?, email = ?, email_verified_at = ?, locked_at = ?, \
             updated_at = ? WHERE id = ?",
            vec![
                text_or_null(user.name.as_deref()),
                user.email.as_str().into(),
                millis_or_null(user.email_verified_at),
                millis_or_null(user.locked_at),
                millis(now),
                user.id.as_str().into(),
            ],
        )?;
        if written == 0 {
            return Err(StorageError::NotFound.into());
        }
        self.find_one("id", user.id.as_str())?
            .ok_or_else(|| StorageError::NotFound.into())
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        for table in ["torii_sessions", "torii_tokens", "torii_oauth_accounts"] {
            self.db.exec(
                &format!("DELETE FROM {table} WHERE user_id = ?"),
                vec![id.as_str().into()],
            )?;
        }
        self.db.exec(
            "DELETE FROM torii_users WHERE id = ?",
            vec![id.as_str().into()],
        )
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        let now = Utc::now();
        self.db.exec(
            "UPDATE torii_users SET email_verified_at = ?, updated_at = ? WHERE id = ?",
            vec![millis(now), millis(now), user_id.as_str().into()],
        )
    }
}
