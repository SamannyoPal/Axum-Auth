use argon2::password_hash::rand_core::Error;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::fmt;
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorMessages {
    EmptyPassword,
    ExceededMaxPasswordLength(usize),
    HashingError,
    InvalidHashFormat,
    InvalidToken,
    InternalServerError,
    InvalidCredentials,
    EmailExist,
    UserNoLongerExist,
    TokenNotProvided,
    PermissionDenied,
    UserNotAuthenticated,
}

impl ErrorMessages {
    fn to_str(&self) -> String {
        match self {
            ErrorMessages::EmptyPassword => "Password cannot be empty".to_owned(),
            ErrorMessages::ExceededMaxPasswordLength(len) => {
                format!("Password must not be more than {} characters", len)
            }
            ErrorMessages::HashingError => "Error while hashing password".to_owned(),
            ErrorMessages::InvalidHashFormat => "Invalid password hash format".to_owned(),
            ErrorMessages::InvalidToken => "Authentication token is invalid or expired".to_owned(),
            ErrorMessages::InternalServerError => {
                "Internal server error. Please Try again later".to_owned()
            }
            ErrorMessages::InvalidCredentials => "Email or Password is wrong".to_owned(),
            ErrorMessages::EmailExist => "A user with this email already exists".to_owned(),
            ErrorMessages::UserNoLongerExist => {
                "User belonging to this token no longer exists".to_owned()
            }
            ErrorMessages::TokenNotProvided => "Please provide a token".to_owned(),
            ErrorMessages::PermissionDenied => {
                "You are not allowed to perform this action".to_owned()
            }
            ErrorMessages::UserNotAuthenticated => {
                "Authentication required. Please log in".to_owned()
            }
        }
    }
}

impl ToString for ErrorMessages {
    fn to_string(&self) -> String {
        self.to_str().to_owned()
    }
}

#[derive(Debug, Clone)]
pub struct HttpError {
    message: String,
    status: StatusCode,
}

impl HttpError {
    pub fn new(message: impl Into<String>, status: StatusCode) -> Self {
        HttpError {
            message: message.into(),
            status,
        }
    }

    pub fn ServerError(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn BadRequest(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn UniqueConstraintViolation(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::CONFLICT,
        }
    }

    pub fn Unauthorized(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    pub fn into_http_response(self) -> Response {
        let json_response = Json(ErrorResponse {
            status: "fail".to_string(),
            message: self.message.clone(),
        });
        (self.status, json_response).into_response()
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HttpError: Message:{}, status:{}",
            self.message, self.status
        )
    }
}

impl std::error::Error for HttpError {}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        self.into_http_response()
    }
}
