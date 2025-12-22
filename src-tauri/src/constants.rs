//! Application constants and configuration values
//!
//! This module contains all configuration constants used throughout the application.
//! Centralizing constants makes it easier to maintain and modify application behavior.

/// Main web application URL
pub const APP_URL: &str = "https://app.elulib.com";

/// Host for connectivity verification
pub const CONNECTIVITY_HOST: &str = "app.elulib.com";

/// Port for connectivity verification
pub const CONNECTIVITY_PORT: u16 = 443;

/// Timeout for connectivity verification (seconds)
/// This is the initial timeout - retries use exponential backoff
pub const CONNECTIVITY_TIMEOUT_SECS: u64 = 2;

/// Read/write timeout for TCP connections (seconds)
pub const TCP_RW_TIMEOUT_SECS: u64 = 1;

/// Maximum number of retry attempts for connectivity check
pub const MAX_CONNECTIVITY_RETRIES: u32 = 2;

/// Base delay for exponential backoff (milliseconds)
pub const RETRY_BASE_DELAY_MS: u64 = 500;

/// Application title
pub const APP_TITLE: &str = "élulib";

/// Main window dimensions
pub const WINDOW_WIDTH: f64 = 1024.0;
pub const WINDOW_HEIGHT: f64 = 768.0;

/// Minimum window dimensions
pub const MIN_WINDOW_WIDTH: f64 = 480.0;
pub const MIN_WINDOW_HEIGHT: f64 = 600.0;

/// Delay before checking for updates (seconds)
pub const UPDATE_CHECK_DELAY_SECS: u64 = 5;

/// Local fallback URL for offline display
pub const LOCAL_ERROR_PAGE_URL: &str = "http://localhost/connection-error.html";

/// Authorized identifier for keyring storage
pub const KEYRING_SERVICE_ID: &str = "com.elulib.desktop";

/// Maximum allowed size for keyring username
pub const MAX_USERNAME_LENGTH: usize = 128;

/// Maximum allowed size for a stored token
pub const MAX_TOKEN_LENGTH: usize = 4096;

