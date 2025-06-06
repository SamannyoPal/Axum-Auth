#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret_key: String,
    pub jwt_maxage: i64,
    pub port: u16,
}

impl Config {
    pub fn init() -> Config {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret_key = std::env::var("JWT_SECRET_KEY").expect("JWT_SECRET must be set");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("MAX_AGE must be set");

        Config {
            database_url,
            jwt_secret_key,
            jwt_maxage: jwt_maxage.parse::<i64>().unwrap(),
            port: 8000,
        }
    }
}
