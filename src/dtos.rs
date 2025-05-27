use chrono::prelude::*;
use core::str;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::{User, UserRole};

#[derive(Debug, Serialize, Deserialize, Validate, Clone, Default)]
pub struct RegisterUserDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Invalid email")
    )]
    pub email: String,
    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub password: String,
    #[validate(
        length(min = 1, message = "Password confirmation is required"),
        must_match(other = "password", message = "Password do not match")
    )]
    #[serde(rename = "passwordConfirm")]
    pub password_confirmation: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone, Default)]
pub struct LoginUserDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Invalid email")
    )]
    pub email: String,
    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub password: String,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)] //change
pub struct RequestQueryDto {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)] //change
pub struct FilterUserDto {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub verified: bool,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl FilterUserDto {
    pub fn filter_user(user: &User) -> Self {
        FilterUserDto {
            id: user.id.to_string(),
            name: user.username.to_owned(),
            email: user.email.to_owned(),
            role: user.role.to_str().to_string(),
            verified: user.verified,
            created_at: user.created_at.unwrap(),
            updated_at: user.updated_at.unwrap(),
        }
    }

    pub fn filter_users(user: &[User]) -> Vec<FilterUserDto> {
        user.iter().map(FilterUserDto::filter_user).collect()
    }
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)] //change
pub struct UserData {
    pub user: FilterUserDto,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)] //change
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)] //change
pub struct UserListResponseDto {
    pub status: String,
    pub users: Vec<FilterUserDto>,
    pub result: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserLoginResponseDto {
    pub status: String,
    pub token: String,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)] //change
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct NameUpdateDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct RoleUpdateDto {
    #[validate(custom = "validate_user_role")]
    pub role: UserRole,
}

pub fn validate_user_role(role: &UserRole) -> Result<(), validator::ValidationError> {
    match role {
        UserRole::Admin | UserRole::User => Ok(()),
        _ => Err(validator::ValidationError::new("Invalid role")),
    }
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct UserPasswordUpdateDto {
    #[validate(
        length(min = 1, message = "New password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub new_password: String,
    #[validate(
        length(min = 1, message = "Password confirmation is required"),
        length(min = 6, message = "Password must be at least 6 characters"),
        must_match(other = "new_password", message = "Password do not match")
    )]
    pub new_password_confirm: String,
    #[validate(
        length(min = 1, message = "Old password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub old_password: String,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)] // change
pub struct VerifyEmailQueryDto {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)]
pub struct ForgotPasswordRequestDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Invalid email")
    )]
    pub email: String,
}

#[derive(Serialize, Deserialize, Validate, Debug, Clone)]
pub struct ResetPasswordRequestDto {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub new_password: String,
    #[validate(
        length(min = 1, message = "Password confirmation is required"),
        length(min = 6, message = "Password must be at least 6 characters"),
        must_match(other = "new_password", message = "Password do not match")
    )]
    pub new_password_confirm: String,
}
