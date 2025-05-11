use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::ErrorMessages;

const MAX_PASSWORD_LENGTH: usize = 64;

pub fn hash(password: impl Into<String>) -> Result<String, ErrorMessages> {
    let password = password.into();
    if password.is_empty() {
        return Err(ErrorMessages::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessages::ExceededMaxPasswordLength(
            MAX_PASSWORD_LENGTH,
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ErrorMessages::HashingError)?
        .to_string();
    Ok(hashed_password)
}

pub fn compare(password: &str, hashed_password: &str) -> Result<bool, ErrorMessages> {
    if password.is_empty() {
        return Err(ErrorMessages::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessages::ExceededMaxPasswordLength(
            MAX_PASSWORD_LENGTH,
        ));
    }

    let parsed_hash =
        PasswordHash::new(hashed_password).map_err(|_| ErrorMessages::InvalidHashFormat)?;

    let password_matched = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_or(false, |_| true);
    Ok(password_matched)
}
