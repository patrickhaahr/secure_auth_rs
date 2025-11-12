use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Identifier for rate limiting - either IP address or browser fingerprint hash
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) enum ClientIdentifier {
    Ip(IpAddr),
    Fingerprint(String),
}

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<ClientIdentifier, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub fn check_rate_limit(&self, identifier: ClientIdentifier) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();

        // Get or create entry for this identifier
        let client_requests = requests.entry(identifier).or_insert_with(Vec::new);

        // Remove requests outside the time window
        client_requests.retain(|&time| now.duration_since(time) < self.window);

        // Check if under limit
        if client_requests.len() < self.max_requests {
            client_requests.push(now);
            true
        } else {
            false
        }
    }

    /// Extract browser fingerprint from request headers
    /// Combines User-Agent, Accept-Language, and custom X-Browser-Fingerprint header
    fn extract_fingerprint(headers: &HeaderMap) -> Option<String> {
        // Check for custom fingerprint header first
        if let Some(fp) = headers.get("x-browser-fingerprint") {
            if let Ok(fp_str) = fp.to_str() {
                if !fp_str.is_empty() {
                    return Some(fp_str.to_string());
                }
            }
        }

        // Fallback: create fingerprint from available headers
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let accept_language = headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let accept_encoding = headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if user_agent.is_empty() {
            return None;
        }

        // Create hash of combined headers
        let combined = format!("{}{}{}", user_agent, accept_language, accept_encoding);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        
        Some(hash)
    }

    pub async fn middleware(
        &self,
        req: Request,
        next: Next,
    ) -> Response {
        // Try to get IP address first
        let identifier = if let Some(addr) = req.extensions().get::<std::net::SocketAddr>() {
            ClientIdentifier::Ip(addr.ip())
        } else {
            // Fallback to browser fingerprint
            match Self::extract_fingerprint(req.headers()) {
                Some(fingerprint) => {
                    tracing::debug!("Using browser fingerprint for rate limiting: {}", &fingerprint[..8]);
                    ClientIdentifier::Fingerprint(fingerprint)
                }
                None => {
                    tracing::warn!("Unable to determine client IP address or browser fingerprint");
                    return (
                        StatusCode::BAD_REQUEST,
                        "Unable to identify client for rate limiting",
                    )
                        .into_response();
                }
            }
        };

        if !self.check_rate_limit(identifier) {
            return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
        }

        next.run(req).await
    }
}
