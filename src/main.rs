mod crypto;
mod db;

use axum::{Router, routing::get};
use sqlx::Pool;
use sqlx::Sqlite;
use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder, 
    GovernorLayer,
};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Pool<Sqlite>>,
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize database connection pool
    let pool = db::init_pool()
        .await
        .expect("Failed to initialize database pool");

    println!("✓ Database connected and migrations completed");

    let app_state = AppState { db: Arc::new(pool) };

    // Configure rate limiting: 10 requests per second with burst of 20
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(20)
            .finish()
            .expect("Failed to build rate limiter configuration")
    );

    // Create router with rate limiting
    let app = Router::new()
        .route("/health", get(health_check))
        .layer(GovernorLayer::new(governor_conf))
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind to port 3000");

    println!("✓ Server running on http://127.0.0.1:3000");

    axum::serve(listener, app).await.expect("Server failed");
}

async fn health_check() -> &'static str {
    "OK"
}
