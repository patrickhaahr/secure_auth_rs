# Secure Auth RS - Agent Guidelines

## Project Overview
Rust Axum web application implementing a three-phase authentication/authorization flow:
1. **Authentication** - Account ID generated → TOTP 2FA verification → JWT token issued
2. **Authorization** - User submits CPR (Danish personal ID) for validation
3. **Access** - Authenticated + CPR-validated users can access protected API endpoints

## Build/Test/Lint Commands
- **Build**: `cargo build` or `cargo build --release`
- **Run**: `cargo run`
- **Test all**: `cargo test`
- **Test single**: `cargo test test_name` (e.g., `cargo test test_generate_account_id_length`)
- **Test module**: `cargo test module::submodule` (e.g., `cargo test crypto::account`)
- **Lint**: `cargo clippy` or `cargo clippy -- -D warnings`
- **Format**: `cargo fmt` (check: `cargo fmt -- --check`)

## Code Style
- **Edition**: Rust 2024
- **Imports**: Group external crates first, then internal modules (`use crate::{...}`)
- **Security-sensitive types**: Custom Debug implementations that redact secrets (see `TotpSecret`, `CprData`)
- **Error handling**: Use `Result<T, E>`, log errors with `tracing::error!`, return meaningful HTTP status codes
- **Naming**: snake_case for functions/variables, PascalCase for types, descriptive names for security operations
- **Comments**: Document security properties, data flows, and PII handling explicitly
- **Async**: Use `async fn` with tokio runtime, `#[tokio::main]` for entry point
- **Types**: Explicit types preferred, use `#[derive(Serialize, Deserialize, FromRow)]` for models
- **Formatting**: Standard rustfmt (4-space indentation)

## Security Practices
- Never log or debug-print sensitive data (CPR, TOTP secrets, encryption keys)
- Use `zeroize` for clearing sensitive memory
- All crypto operations must use established libraries (argon2, aes-gcm, totp-rs)
- CSRF protection required on all POST routes except rate-limited auth endpoints
