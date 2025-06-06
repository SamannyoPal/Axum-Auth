mod config;
mod db;
mod dtos;
mod error;
mod handler;
mod mail;
mod middleware;
mod models;
mod routes;
mod utils;

use axum::{
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    Extension,
};
use chrono::format;
use config::Config;
use db::DBClient;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tracing_subscriber::filter::LevelFilter;

#[derive(Debug, Clone)]
pub struct AppState {
    pub env: Config,
    pub db_client: DBClient,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    dotenv().ok();

    let config = Config::init();
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("Connected to database is successful");
            pool
        }
        Err(e) => {
            println!("Failed to connect to database: {:?}", e);
            std::process::exit(1);
        }
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_credentials(true);

    let db_client = DBClient::new(pool);

    let app_state = AppState {
        env: config.clone(),
        db_client,
    };

    // Initialize the server
    let app = axum::Router::new()
        .layer(Extension(app_state))
        .layer(cors.clone());

    println!(
        "{}",
        format!("Server is running on http://localhost:{}", config.port)
    );
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &config.port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
