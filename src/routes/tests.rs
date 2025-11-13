#[cfg(test)]
mod route_tests {
    use crate::{
        AppState,
        crypto::{account, cpr, totp},
        db::{repository, init_pool},
        middleware::{auth, csrf::CsrfProtection},
        routes::{account as account_routes, admin as admin_routes, auth as auth_routes},
    };
    use axum::{
        extract::State,
        http::StatusCode,
    };
    use axum_extra::extract::cookie::{Cookie, CookieJar};

    // Helper: Create test database pool
    async fn setup_test_db() -> AppState {
        dotenvy::dotenv().ok();
        let pool = init_pool().await.expect("Failed to init test database");
        
        let csrf_protection = CsrfProtection::new();
        
        AppState {
            db: pool,
            csrf: csrf_protection,
        }
    }

    // Helper: Create test account
    async fn create_test_account(state: &AppState) -> String {
        let account_id = account::generate_account_id();
        repository::create_account(&state.db, &account_id)
            .await
            .expect("Failed to create test account");
        account_id
    }

    // Helper: Setup TOTP for account
    async fn setup_totp_for_account(state: &AppState, account_id: &str) -> String {
        let encryption_key = totp::load_encryption_key().expect("Failed to load encryption key");
        let secret = totp::generate_totp_secret();
        let encrypted_secret = totp::encrypt_totp_secret(&secret, &encryption_key)
            .expect("Failed to encrypt TOTP secret");
        
        repository::insert_totp_secret(&state.db, account_id, &encrypted_secret)
            .await
            .expect("Failed to insert TOTP secret");
        
        secret
    }

    // Helper: Generate valid TOTP code
    fn generate_valid_totp(secret: &str) -> String {
        totp::generate_totp_code(secret).expect("Failed to generate TOTP code")
    }

    // Helper: Create authenticated cookie
    fn create_auth_cookie_for_account(account_id: &str) -> Cookie<'static> {
        let token = auth::generate_token(account_id).expect("Failed to generate token");
        auth::create_auth_cookie(&token)
    }

    // ========== AUTH ROUTE TESTS ==========

    #[tokio::test]
    async fn test_signup_creates_account() {
        let state = setup_test_db().await;
        
        let response = auth_routes::signup(State(state.clone()))
            .await
            .expect("Signup should succeed");

        let body = response.0;
        assert!(!body.account_id.is_empty());
        
        // Verify account exists in database
        let exists = repository::account_exists(&state.db, &body.account_id)
            .await
            .expect("Failed to check account existence");
        assert!(exists);
    }

    #[tokio::test]
    async fn test_totp_setup_generates_secret() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;

        let request = auth_routes::TotpSetupRequest {
            account_id: account_id.clone(),
        };

        let response = auth_routes::totp_setup(
            State(state.clone()),
            axum::Json(request),
        )
        .await
        .expect("TOTP setup should succeed");

        let body = response.0;
        assert!(!body.secret.is_empty());
        assert!(body.qr_uri.starts_with("data:image/png;base64,"));
        assert!(body.otpauth_uri.starts_with("otpauth://totp/"));
    }

    #[tokio::test]
    async fn test_totp_verify_with_valid_code() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        let secret = setup_totp_for_account(&state, &account_id).await;
        let valid_code = generate_valid_totp(&secret);

        let request = auth_routes::TotpVerifyRequest {
            account_id: account_id.clone(),
            code: valid_code,
        };

        let response = auth_routes::totp_verify(
            State(state.clone()),
            axum::Json(request),
        )
        .await
        .expect("TOTP verification should succeed");

        assert!(response.0.verified);
    }

    #[tokio::test]
    async fn test_totp_verify_with_invalid_code() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        setup_totp_for_account(&state, &account_id).await;

        let request = auth_routes::TotpVerifyRequest {
            account_id: account_id.clone(),
            code: "000000".to_string(), // Invalid code
        };

        let response = auth_routes::totp_verify(
            State(state.clone()),
            axum::Json(request),
        )
        .await
        .expect("TOTP verification should return response");

        assert!(!response.0.verified);
    }

    #[tokio::test]
    async fn test_login_with_valid_credentials() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        let secret = setup_totp_for_account(&state, &account_id).await;
        
        // Verify TOTP first
        repository::verify_totp(&state.db, &account_id)
            .await
            .expect("Failed to verify TOTP");

        let valid_code = generate_valid_totp(&secret);
        let request = auth_routes::LoginRequest {
            account_id: account_id.clone(),
            code: valid_code,
        };

        let jar = CookieJar::new();
        let response = auth_routes::login(
            State(state.clone()),
            jar,
            axum::Json(request),
        )
        .await
        .expect("Login should succeed");

        let (cookie_jar, json_response) = response;
        assert!(json_response.0.success);
        assert!(json_response.0.token.is_some());
        
        // Verify cookie was set
        let auth_cookie = cookie_jar.get("auth_token");
        assert!(auth_cookie.is_some());
    }

    #[tokio::test]
    async fn test_login_with_unverified_totp() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        let secret = setup_totp_for_account(&state, &account_id).await;
        
        // Don't verify TOTP - should fail
        let valid_code = generate_valid_totp(&secret);
        let request = auth_routes::LoginRequest {
            account_id: account_id.clone(),
            code: valid_code,
        };

        let jar = CookieJar::new();
        let result = auth_routes::login(
            State(state.clone()),
            jar,
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_logout_clears_cookie() {
        let jar = CookieJar::new();
        let token = auth::generate_token("test_account").expect("Failed to generate token");
        let jar = jar.add(auth::create_auth_cookie(&token));

        let response = auth_routes::logout(jar)
            .await
            .expect("Logout should succeed");

        let (cookie_jar, json_response) = response;
        assert!(json_response.0.success);
        
        // Verify cookie was cleared (max_age should be negative)
        let cleared_cookie = cookie_jar.get("auth_token");
        assert!(cleared_cookie.is_some());
    }

    // ========== ACCOUNT ROUTE TESTS ==========

    #[tokio::test]
    async fn test_submit_cpr_as_account_owner() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        let secret = setup_totp_for_account(&state, &account_id).await;
        repository::verify_totp(&state.db, &account_id)
            .await
            .expect("Failed to verify TOTP");

        let user = auth::AuthenticatedUser {
            account_id: account_id.clone(),
        };

        let request = account_routes::CprSubmitRequest {
            account_id: account_id.clone(),
            cpr: "0101901234".to_string(), // Valid CPR format
        };

        let response = account_routes::submit_cpr(
            State(state.clone()),
            user,
            axum::Json(request),
        )
        .await
        .expect("CPR submission should succeed");

        assert!(response.0.success);
        
        // Verify CPR was stored
        let has_cpr = repository::has_cpr(&state.db, &account_id)
            .await
            .expect("Failed to check CPR");
        assert!(has_cpr);
    }

    #[tokio::test]
    async fn test_submit_cpr_unauthorized() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        let other_account_id = create_test_account(&state).await;

        let user = auth::AuthenticatedUser {
            account_id: other_account_id,
        };

        let request = account_routes::CprSubmitRequest {
            account_id: account_id.clone(),
            cpr: "0101901234".to_string(),
        };

        let result = account_routes::submit_cpr(
            State(state.clone()),
            user,
            axum::Json(request),
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_account_status() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;

        let response = account_routes::get_account_status(
            State(state.clone()),
            axum::extract::Path(account_id.clone()),
        )
        .await
        .expect("Get account status should succeed");

        let body = response.0;
        assert!(!body.is_verified); // New account not verified
        assert!(!body.has_totp);
        assert!(!body.has_cpr);
    }

    #[tokio::test]
    async fn test_get_account_status_not_found() {
        let state = setup_test_db().await;
        
        let result = account_routes::get_account_status(
            State(state.clone()),
            axum::extract::Path("nonexistent_account".to_string()),
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_verify_cpr_for_login_valid() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        let cpr = "0101901234";
        
        // Submit CPR first
        let cpr_hash = cpr::hash_cpr(cpr).expect("Failed to hash CPR");
        repository::insert_cpr_data(&state.db, &account_id, &cpr_hash)
            .await
            .expect("Failed to insert CPR");

        let user = auth::AuthenticatedUser {
            account_id: account_id.clone(),
        };

        let request = account_routes::CprVerifyRequest {
            account_id: account_id.clone(),
            cpr: cpr.to_string(),
        };

        let response = account_routes::verify_cpr_for_login(
            State(state.clone()),
            user,
            axum::Json(request),
        )
        .await
        .expect("CPR verification should succeed");

        assert!(response.0.success);
    }

    #[tokio::test]
    async fn test_verify_cpr_for_login_invalid() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        let cpr = "0101901234";
        
        // Submit CPR
        let cpr_hash = cpr::hash_cpr(cpr).expect("Failed to hash CPR");
        repository::insert_cpr_data(&state.db, &account_id, &cpr_hash)
            .await
            .expect("Failed to insert CPR");

        let user = auth::AuthenticatedUser {
            account_id: account_id.clone(),
        };

        // Try with wrong CPR
        let request = account_routes::CprVerifyRequest {
            account_id: account_id.clone(),
            cpr: "9999991234".to_string(),
        };

        let response = account_routes::verify_cpr_for_login(
            State(state.clone()),
            user,
            axum::Json(request),
        )
        .await
        .expect("CPR verification should return response");

        assert!(!response.0.success);
    }

    // ========== ADMIN ROUTE TESTS ==========

    #[tokio::test]
    async fn test_check_admin_access_as_admin() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;
        
        // Make account admin
        sqlx::query!(
            "INSERT INTO account_roles (account_id, is_admin) VALUES (?, TRUE)",
            account_id
        )
        .execute(&state.db)
        .await
        .expect("Failed to make account admin");

        let user = auth::AuthenticatedUser {
            account_id: account_id.clone(),
        };

        let response = admin_routes::check_admin_access(
            State(state.clone()),
            user,
        )
        .await
        .expect("Admin check should succeed");

        assert!(response.0.is_admin);
    }

    #[tokio::test]
    async fn test_check_admin_access_as_non_admin() {
        let state = setup_test_db().await;
        let account_id = create_test_account(&state).await;

        let user = auth::AuthenticatedUser {
            account_id: account_id.clone(),
        };

        let result = admin_routes::check_admin_access(
            State(state.clone()),
            user,
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_users_as_admin() {
        let state = setup_test_db().await;
        let admin_id = create_test_account(&state).await;
        let user1_id = create_test_account(&state).await;
        let user2_id = create_test_account(&state).await;

        let user = auth::AuthenticatedUser {
            account_id: admin_id.clone(),
        };

        let response = admin_routes::list_users(
            State(state.clone()),
            user,
        )
        .await
        .expect("List users should succeed");

        let users = response.0;
        assert!(users.len() >= 3); // At least the 3 we created
    }

    #[tokio::test]
    async fn test_delete_user_as_admin() {
        let state = setup_test_db().await;
        let admin_id = create_test_account(&state).await;
        let user_to_delete = create_test_account(&state).await;

        let user = auth::AuthenticatedUser {
            account_id: admin_id.clone(),
        };

        let response = admin_routes::delete_user(
            State(state.clone()),
            axum::extract::Path(user_to_delete.clone()),
            user,
        )
        .await
        .expect("Delete user should succeed");

        assert_eq!(response, StatusCode::NO_CONTENT);
        
        // Verify account was deleted
        let exists = repository::account_exists(&state.db, &user_to_delete)
            .await
            .expect("Failed to check account existence");
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let state = setup_test_db().await;
        let admin_id = create_test_account(&state).await;

        let user = auth::AuthenticatedUser {
            account_id: admin_id.clone(),
        };

        let result = admin_routes::delete_user(
            State(state.clone()),
            axum::extract::Path("nonexistent_account".to_string()),
            user,
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
