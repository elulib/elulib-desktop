//! Rate limiting module for command protection
//!
//! Provides rate limiting functionality to prevent abuse of sensitive commands.
//! Uses a simple in-memory sliding window approach suitable for desktop applications.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate limiter state
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of operation type to request timestamps
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    /// Creates a new rate limiter
    pub fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Checks if an operation is allowed based on rate limits
    /// 
    /// # Arguments
    /// * `operation` - The operation identifier (e.g., "set_token", "get_token")
    /// * `max_requests` - Maximum number of requests allowed
    /// * `window_seconds` - Time window in seconds
    /// 
    /// # Returns
    /// * `Ok(())` if the operation is allowed
    /// * `Err(String)` if rate limit is exceeded
    pub fn check_rate_limit(
        &self,
        operation: &str,
        max_requests: u32,
        window_seconds: u64,
    ) -> Result<(), String> {
        let mut requests = self.requests.lock()
            .map_err(|e| format!("Rate limiter lock error: {}", e))?;
        let now = Instant::now();
        let window = Duration::from_secs(window_seconds);

        // Get or create the request list for this operation
        let operation_requests = requests.entry(operation.to_string()).or_insert_with(Vec::new);

        // Remove requests outside the time window
        operation_requests.retain(|&timestamp| now.duration_since(timestamp) < window);

        // Check if we've exceeded the limit
        if operation_requests.len() >= max_requests as usize {
            return Err(format!(
                "Rate limit exceeded: maximum {} requests per {} seconds for operation '{}'",
                max_requests, window_seconds, operation
            ));
        }

        // Add current request
        operation_requests.push(now);

        Ok(())
    }

    /// Cleans up old entries to prevent memory growth
    /// 
    /// Removes entries older than 1 hour and empty operation buckets.
    /// This should be called periodically to prevent unbounded memory growth.
    /// 
    /// # Errors
    /// 
    /// Logs errors but does not propagate them, as cleanup failures are non-critical.
    pub fn cleanup(&self) {
        let mut requests = match self.requests.lock() {
            Ok(guard) => guard,
            Err(e) => {
                log::warn!("Rate limiter lock error during cleanup: {}", e);
                return;
            }
        };
        let now = Instant::now();
        let max_age = Duration::from_secs(3600); // 1 hour

        requests.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < max_age);
            !timestamps.is_empty()
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

