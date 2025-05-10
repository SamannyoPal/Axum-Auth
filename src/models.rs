use chrono::prelude::*;
use serde::{ser, Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}
impl UserRole {
    pub fn to_str(&self) -> &str {
        match self {
            UserRole::Admin => "Admin",
            UserRole::User => "User",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow, sqlx::Type)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
    pub verified: bool,
    pub verification_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}
