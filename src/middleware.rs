use std::sync::Arc;

use axum::{
    extract::{FromRef, Request},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Extension,
};

use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};

use crate::{
    db::UserExt,
    error::{ErrorMessages, HttpError},
    models::{User, UserRole},
    utils::token,
    AppState,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddleware {
    pub user: User,
}

pub async fn auth(
    cookie_jar: CookieJar,
    Extension(app_state): Extension<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, HttpError> {
    let cookies = cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_string())
                    } else {
                        None
                    }
                })
        });

    let token = cookies
        .ok_or_else(|| HttpError::Unauthorized(ErrorMessages::TokenNotProvided.to_string()))?;

    let token_details = match token::decode_token(token, app_state.env.jwt_secret_key.as_bytes()) {
        Ok(token_details) => token_details,
        Err(_) => {
            return Err(HttpError::Unauthorized(
                ErrorMessages::InvalidToken.to_string(),
            ));
        }
    };

    let user_id = uuid::Uuid::parse_str(&token_details.to_string())
        .map_err(|_| HttpError::Unauthorized(ErrorMessages::InvalidToken.to_string()))?;

    let user = app_state
        .db_client
        .get_user(Some(user_id), None, None, None)
        .await
        .map_err(|_| HttpError::Unauthorized(ErrorMessages::UserNoLongerExist.to_string()))?;

    let user =
        user.ok_or_else(|| HttpError::Unauthorized(ErrorMessages::UserNoLongerExist.to_string()))?;

    req.extensions_mut()
        .insert(JWTAuthMiddleware { user: user.clone() }); // Check user later to reduce.

    Ok(next.run(req).await)
}

pub async fn role_check(
    Extension(_app_state): Extension<Arc<AppState>>,
    req: Request,
    next: Next,
    required_roles: Vec<UserRole>,
) -> Result<impl IntoResponse, HttpError> {
    let user = req
        .extensions()
        .get::<JWTAuthMiddleware>()
        .ok_or_else(|| HttpError::Unauthorized(ErrorMessages::UserNotAuthenticated.to_string()))?;

    if !required_roles.contains(&user.user.role) {
        return Err(HttpError::new(
            ErrorMessages::PermissionDenied.to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    Ok(next.run(req).await)
}
