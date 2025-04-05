use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::{User, UserRole};

#[derive(Debug, Clone)]
pub struct DBClient {
    pub pool: Pool<Postgres>,
}

impl DBClient {
    pub fn new(Pool: Pool<Postgres>) -> Self {
        DBClient { pool }
    }
}

#[async_trait]
pub trait UserExt {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        email: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error>;

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<user>, sqlx::Error>;

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expires_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error>;

    async fn get_user_count(&self) -> Result<i64, sqlx::Error>;

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: T,
    ) -> Result<User, sqlx::Error>;

    async fn update_user_role(&self, user_id: Uuid, role: UserRole) -> Result<User, sqlx::Error>;

    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error>;

    async fn verified_token(&self, token: &str) -> Result<(), sqlx::Error>;

    async fn add_verified_token(
        &self,
        user_id: Uuid,
        token: &str,
        token_expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error>;
}

#[async_trait]
impl UserExt for DBClient {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let mut user: Option<User> = None;
        if let Some(user_id) = user_id {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, username, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE id = $1"#,
                user_id,
            ).fetch_optional(&self.pool).await?;
        } else if let Some(name) = name {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, username, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE username = $1"#,
                name,
            ).fetch_optional(&self.pool).await?;
        } else if let Some(email) = email {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, username, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE email = $1"#,
                email,
            ).fetch_optional(&self.pool).await?;
        } else if let Some(token) = token {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, username, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users WHERE verification_token = $1"#,
                token,
            ).fetch_optional(&self.pool).await?;
        }
        Ok(user)
    }

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error> {
        let offset = (page - 1) * limit as u32;
        let users = sqlx::query_as!(
            User,
            r#"SELECT id, username, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole" FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2 "#,
            limit as i64,
            offset as i64,
        ).fetch_all(&self.pool).await?;
        Ok(users)
    }

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        verification_token: T,
        token_expires_at: DateTime<Utc>,
    ) -> Result<User, sqlx::Error> {
        let name = name.into(); //maybe change
        let email = email.into();
        let password = password.into();
        let verification_token = verification_token.into();
        let token_expires_at = token_expires_at; //maybe change
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users(username, email, password, verification_token, token_expires_at)
            VALUES($1, $2, $3, $4, $5)
            RETURNING id, username, email, password, verified, created_at, updated_at, verification_token, token_expires_at, role as "role: UserRole"
            "#,
            name,
            email,
            password,
            verification_token,
            token_expires_at,
        ).fetch_one(&self.pool).await?;
        Ok(user)
    }

    async fn get_user_count(&self) -> Result<i64, sqlx::Error> {
        // Implementation here
        Ok(0)
    }

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: T,
    ) -> Result<User, sqlx::Error> {
        // Implementation here
        Ok(User::default())
    }

    async fn update_user_role(&self, user_id: Uuid, role: UserRole) -> Result<User, sqlx::Error> {
        // Implementation here
        Ok(User::default())
    }

    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error> {
        // Implementation here
        Ok(User::default())
    }

    async fn verified_token(&self, token: &str) -> Result<(), sqlx::Error> {
        // Implementation here
        Ok(())
    }

    async fn add_verified_token(
        &self,
        user_id: Uuid,
        token: &str,
        token_expires_at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        // Implementation here
        Ok(())
    }
}
// pub trait DBClientTrait {
//     async fn create_user(&self, user: User) -> Result<User, sqlx::Error>;
//     async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, sqlx::Error>;
//     async fn get_user_by_email(&self, email: String) -> Result<Option<User>, sqlx::Error>;
//     async fn update_user(&self, user: User) -> Result<User, sqlx::Error>;
//     async fn delete_user(&self, id: Uuid) -> Result<(), sqlx::Error>;
// }
