use std::sync::Arc;

use axum::extract::Query;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::Extension;
use axum::Json;
use axum::Router;

use axum_extra::extract::cookie::{self, Cookie};

use chrono::{Duration, Utc};
use validator::Validate;

use crate::db::UserExt;
use crate::dtos::{
    ForgotPasswordRequestDto, LoginUserDto, ResetPasswordRequestDto, Response,
    UserLoginResponseDto, VerifyEmailQueryDto,
};
use crate::mail::mails::{send_forget_password_email, send_verification_email, send_welcome_email};
use crate::utils::{password, token};
use crate::{
    dtos::RegisterUserDto,
    error::{ErrorMessages, HttpError},
    AppState,
};

pub fn auth_handler() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/verify-email", get(verify_email))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
}

pub async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let verification_token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::days(1);

    let hash_password =
        password::hash(&body.password).map_err(|e| HttpError::ServerError(e.to_string()))?;

    let result = app_state
        .db_client
        .save_user(
            &body.name,
            &body.email,
            &hash_password,
            &verification_token,
            expires_at,
        )
        .await;

    match result {
        Ok(_user) => {
            let send_email_result =
                send_verification_email(&body.email, &body.name, &verification_token).await;
            if let Err(e) = send_email_result {
                eprintln!("Failed to send verification email: {:?}", e);
            }
            Ok((
                StatusCode::CREATED,
                Json(Response {
                    status: "success",
                    message:
                        "User registered successfully. Please check your email for verification."
                            .to_string(),
                }),
            ))
        }
        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                Err(HttpError::UniqueConstraintViolation(
                    ErrorMessages::EmailExist.to_string(),
                ))
            } else {
                Err(HttpError::ServerError(db_err.to_string()))
            }
        }
        Err(e) => Err(HttpError::ServerError(e.to_string())),
    }
}

pub async fn login(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let user = result.ok_or(HttpError::BadRequest(
        ErrorMessages::InvalidCredentials.to_string(),
    ))?;

    let password_matched = password::compare(&body.password, &user.password)
        .map_err(|_| HttpError::BadRequest(ErrorMessages::InvalidCredentials.to_string()))?;

    if password_matched {
        let token = token::create_token(
            &user.id.to_string(),
            &app_state.env.jwt_secret_key.as_bytes(),
            app_state.env.jwt_maxage,
        )
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

        let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
        let cookie = Cookie::build(("token", token.clone()))
            .path("/")
            .max_age(cookie_duration)
            .http_only(true)
            .build();

        let response = axum::response::Json(UserLoginResponseDto {
            status: "success".to_string(),
            token,
        });

        let mut headers = HeaderMap::new();
        headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());
        let mut response = response.into_response();
        response.headers_mut().extend(headers);
        Ok(response)
    } else {
        Err(HttpError::BadRequest(
            ErrorMessages::InvalidCredentials.to_string(),
        ))
    }
}

pub async fn verify_email(
    Query(query_params): Query<VerifyEmailQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&query_params.token))
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let user = result.ok_or(HttpError::Unauthorized(
        ErrorMessages::InvalidToken.to_string(),
    ))?;

    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::BadRequest(
                "Verification Token has expired".to_string(),
            ))?;
        }
    } else {
        return Err(HttpError::BadRequest(
            "Invalid Verification token".to_string(),
        ))?;
    }

    app_state
        .db_client
        .verified_token(&query_params.token)
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let send_welcome_email_result = send_welcome_email(&user.email, &user.username).await;

    if let Err(e) = send_welcome_email_result {
        eprintln!("Failed to send welcome email: {:?}", e);
    }

    let token = token::create_token(
        &user.id.to_string(),
        app_state.env.jwt_secret_key.as_bytes(),
        app_state.env.jwt_maxage,
    )
    .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
    let cookie = cookie::Cookie::build(("token", token.clone()))
        .path("/")
        .max_age(cookie_duration)
        .http_only(true)
        .build();

    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

    let frontend_url = format!("http://localhost:5173/settings");

    let redirect = Redirect::to(&frontend_url);

    let mut response = redirect.into_response();
    response.headers_mut().extend(headers);
    Ok(response)
}

pub async fn forgot_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<ForgotPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let user = result.ok_or(HttpError::BadRequest("Email not found".to_string()))?;

    let verification_token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(30);

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    app_state
        .db_client
        .add_verified_token(user_id, &verification_token, expires_at)
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let reset_link = format!(
        "http://localhost:5173/reset-password?token={}",
        &verification_token
    );
    let email_sent = send_forget_password_email(&user.email, &reset_link, &user.username).await;

    if let Err(e) = email_sent {
        eprintln!("Failed to send forgot password email: {}", e);
        return Err(HttpError::ServerError("Falied to send email.".to_string()));
    }

    let response = Response {
        message: "Password reset link has been sent to your email.".to_string(),
        status: "success",
    };

    Ok(Json(response))
}

pub async fn reset_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<ResetPasswordRequestDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&body.token))
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let user = result.ok_or(HttpError::BadRequest(
        "Invalid os expired token".to_string(),
    ))?;

    if let Some(expires_at) = user.token_expires_at {
        if Utc::now() > expires_at {
            return Err(HttpError::BadRequest(
                "Verification Token has expired".to_string(),
            ))?;
        }
    } else {
        return Err(HttpError::BadRequest(
            "Invalid verification token.".to_string(),
        ));
    }

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let hash_password =
        password::hash(&body.new_password).map_err(|e| HttpError::ServerError(e.to_string()))?;

    app_state
        .db_client
        .update_user_password(user_id.clone(), hash_password)
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;
    app_state
        .db_client
        .verified_token(&body.token)
        .await
        .map_err(|e| HttpError::ServerError(e.to_string()))?;

    let response = Response {
        message: "Password has been successfully reset.".to_string(),
        status: "success",
    };

    Ok(Json(response))
}
