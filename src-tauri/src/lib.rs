//! élulib Desktop Application - Tauri wrapper for the web application
//!
//! This application provides a native interface to access élulib.com
//! with offline management, notifications, and automatic updates.

pub mod constants;
mod notifications;
pub mod rate_limit;

// === ORGANIZED IMPORTS ===

// Core Tauri
use tauri::{
    command,
    menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem},
    tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState},
    window::Color,
    App, AppHandle, Manager, Runtime, Theme, WebviewUrl, WebviewWindowBuilder,
    image::Image,
};

// Tauri Plugins
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_updater::UpdaterExt;

// Network and async utilities
use std::net::ToSocketAddrs;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;

// File I/O
use std::fs;
use std::path::PathBuf;

// Constants
use constants::*;

// Rate limiting
use rate_limit::RateLimiter;

// === UTILITY FUNCTIONS ===

/// Checks network connectivity securely with retry logic (async version)
/// 
/// Uses an asynchronous approach with DNS resolution, timeout, and exponential backoff retries.
/// This is non-blocking and should be used for all connectivity checks.
/// 
/// # Implementation Details
/// 
/// - Attempts connection with configurable timeout
/// - Implements exponential backoff for retries (up to MAX_CONNECTIVITY_RETRIES)
/// - Tries multiple DNS addresses if available
/// - Uses async timeouts to prevent blocking
/// 
/// # Performance
/// 
/// - First attempt: ~2 seconds timeout
/// - Retries: exponential backoff (500ms, 1000ms, etc.)
/// - Maximum total time: ~4-6 seconds in worst case
/// - Typical case: < 2 seconds if connection is available
/// - Non-blocking: does not freeze UI
/// 
/// # Returns
/// * `true` if connection is available
/// * `false` if connection is not available after all retries
#[cfg_attr(test, allow(dead_code))]
pub async fn check_network_connectivity_async() -> bool {
    // Try with retries using exponential backoff
    for attempt in 0..=MAX_CONNECTIVITY_RETRIES {
        if attempt > 0 {
            // Exponential backoff: 500ms, 1000ms, 2000ms, etc.
            let delay_ms = RETRY_BASE_DELAY_MS * (1 << (attempt - 1));
            log::debug!("Retrying connectivity check (attempt {}/{}) after {}ms delay", attempt + 1, MAX_CONNECTIVITY_RETRIES + 1, delay_ms);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        match (CONNECTIVITY_HOST, CONNECTIVITY_PORT).to_socket_addrs() {
            Ok(addresses) => {
                // Try each resolved address
                for address in addresses {
                    let timeout_duration = Duration::from_secs(CONNECTIVITY_TIMEOUT_SECS);
                    match timeout(timeout_duration, TcpStream::connect(&address)).await {
                        Ok(Ok(_stream)) => {
                            if attempt > 0 {
                                log::info!("TCP connection successful to {} via {} (after {} retries)", CONNECTIVITY_HOST, address, attempt);
                            } else {
                                log::debug!("TCP connection successful to {} via {}", CONNECTIVITY_HOST, address);
                            }
                            return true;
                        }
                        Ok(Err(e)) => {
                            log::debug!("TCP connection failed to {} via {} - {}", CONNECTIVITY_HOST, address, e);
                        }
                        Err(_) => {
                            log::debug!("TCP connection timeout to {} via {}", CONNECTIVITY_HOST, address);
                        }
                    }
                }

                if attempt < MAX_CONNECTIVITY_RETRIES {
                    log::debug!("No reachable address for {} on attempt {}, will retry", CONNECTIVITY_HOST, attempt + 1);
                } else {
                    log::debug!("No reachable address for {} after all retries", CONNECTIVITY_HOST);
                }
            }
            Err(e) => {
                if attempt < MAX_CONNECTIVITY_RETRIES {
                    log::debug!("DNS resolution failed for {} on attempt {}: {}, will retry", CONNECTIVITY_HOST, attempt + 1, e);
                } else {
                    log::debug!("DNS resolution failed for {} after all retries: {}", CONNECTIVITY_HOST, e);
                }
            }
        }
    }

    false
}

/// Synchronous wrapper for network connectivity check (for backward compatibility)
/// 
/// This function is deprecated and should only be used in tests.
/// Use `check_network_connectivity_async()` instead.
#[cfg_attr(test, allow(dead_code))]
#[doc(hidden)]
pub fn check_network_connectivity() -> bool {
    // Use tokio runtime for synchronous execution
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        log::error!("Failed to create tokio runtime: {}", e);
        std::process::exit(1);
    });
    rt.block_on(check_network_connectivity_async())
}

/// Validates that the keyring service is authorized
/// 
/// # Arguments
/// * `service` - The service identifier to validate
/// 
/// # Returns
/// * `Ok(())` if the service is authorized
/// * `Err(String)` if the service is not authorized
#[cfg_attr(test, allow(dead_code))]
#[doc(hidden)]
pub fn validate_service(service: &str) -> Result<(), String> {
    let trimmed = service.trim();
    
    // Enhanced validation: length checks
    if trimmed.len() < MIN_SERVICE_LENGTH {
        return Err(format!("Service identifier too short (minimum {} characters)", MIN_SERVICE_LENGTH));
    }
    
    if trimmed.len() > MAX_SERVICE_LENGTH {
        return Err(format!("Service identifier too long (maximum {} characters)", MAX_SERVICE_LENGTH));
    }
    
    // Check for potential injection patterns (basic sanitization)
    if trimmed.contains('\0') || trimmed.contains('\n') || trimmed.contains('\r') {
        return Err("Service identifier contains invalid characters".into());
    }
    
    // Authorized service check
    if trimmed == KEYRING_SERVICE_ID {
        Ok(())
    } else {
        Err("Service not authorized for keyring".into())
    }
}

/// Normalizes and validates a username for the keyring
/// 
/// # Arguments
/// * `username` - The username to normalize
/// 
/// # Returns
/// * `Ok(String)` with the normalized username
/// * `Err(String)` if the username is invalid
#[cfg_attr(test, allow(dead_code))]
#[doc(hidden)]
pub fn normalize_username(username: &str) -> Result<String, String> {
    let trimmed = username.trim();

    if trimmed.is_empty() {
        return Err("Username is missing".into());
    }

    if trimmed.len() > MAX_USERNAME_LENGTH {
        return Err("Username too long".into());
    }

    // Enhanced validation: check for null bytes and control characters
    if trimmed.contains('\0') || trimmed.chars().any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r') {
        return Err("Username contains invalid control characters".into());
    }

    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return Err(
            "Invalid username (allowed characters: a-z, 0-9, ._-@)".into(),
        );
    }

    Ok(trimmed.to_string())
}

/// Validates an authentication token
/// 
/// # Arguments
/// * `token` - The token to validate
/// 
/// # Returns
/// * `Ok(())` if the token is valid
/// * `Err(String)` if the token is invalid
#[cfg_attr(test, allow(dead_code))]
#[doc(hidden)]
pub fn validate_token(token: &str) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("Token is empty or missing".into());
    }

    if token.len() > MAX_TOKEN_LENGTH {
        return Err("Token too large".into());
    }

    // Enhanced validation: check for null bytes (potential injection)
    if token.contains('\0') {
        return Err("Token contains invalid null bytes".into());
    }

    Ok(())
}

/// Logs audit information for token operations without logging sensitive data
/// 
/// # Arguments
/// * `operation` - The operation type ("set_token" or "get_token")
/// * `username` - The username (sanitized for logging)
/// * `success` - Whether the operation succeeded
/// * `error` - Optional error message (if operation failed)
#[cfg_attr(test, allow(dead_code))]
fn log_token_operation_audit(
    operation: &str,
    username: &str,
    success: bool,
    error: Option<&str>,
) {
    // Sanitize username for logging (truncate if too long, mask sensitive parts)
    let sanitized_username = if username.len() > 20 {
        format!("{}...", &username[..20])
    } else {
        username.to_string()
    };

    if success {
        log::info!(
            "Token operation audit: operation='{}', username='{}', status=success",
            operation,
            sanitized_username
        );
    } else {
        log::warn!(
            "Token operation audit: operation='{}', username='{}', status=failed, error='{}'",
            operation,
            sanitized_username,
            error.unwrap_or("unknown")
        );
    }
}

/// Creates the main window and checks connectivity asynchronously
/// 
/// Shows the window immediately with a loading/error page, then navigates to the
/// web application once connectivity is confirmed. This provides instant startup
/// without blocking the UI.
/// 
/// # Network Connectivity Check
/// 
/// The connectivity check uses:
/// - Async non-blocking operations
/// - Configurable timeout (2 seconds per attempt)
/// - Exponential backoff retry mechanism (up to 2 retries)
/// - Multiple DNS address resolution attempts
/// - Runs in background after window is shown
/// 
/// Total maximum time: ~4-6 seconds in worst case (non-blocking)
/// Typical time: < 2 seconds if connection is available
/// Window appears: < 100ms (instant)
/// 
/// # Error Handling
/// 
/// This function handles errors gracefully:
/// - Window creation failures are propagated (critical)
/// - Theme setting failures are logged but non-critical (fallback to system theme)
/// - Network check failures result in offline mode (non-critical)
/// - All errors are logged with appropriate severity levels
/// 
/// # Returns
/// 
/// * `Ok(())` if the window was created successfully
/// * `Err(tauri::Error)` if window creation failed
fn create_main_window(app: &App) -> tauri::Result<()> {
    // Show window immediately with error page (will navigate if online)
    // This provides instant startup without blocking
    let initial_url = WebviewUrl::App("connection-error.html".into());
    log::info!("Creating window immediately for instant startup");

    let window = WebviewWindowBuilder::new(app, "main", initial_url)
        .title(APP_TITLE)
        .background_color(Color(255, 255, 255, 255))
        .inner_size(WINDOW_WIDTH, WINDOW_HEIGHT)
        .min_inner_size(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
        .resizable(true)
        .initialization_script(include_str!("link_handler.js"))
        .decorations(true)
        .prevent_overflow()
        .build()?;

    // Set theme to Light to ensure title bar text is readable in dark mode
    // This forces light theme for the title bar, making text visible
    // 
    // Note: Theme setting failure is non-critical because:
    // 1. The window will fall back to system default theme
    // 2. The application remains fully functional
    // 3. Title bar text may be less readable in dark mode, but the app still works
    // 4. This is a platform-specific feature that may not be available on all systems
    match window.set_theme(Some(Theme::Light)) {
        Ok(_) => {
            log::debug!("Window theme set to Light successfully");
        }
        Err(e) => {
            // Log as warning since this is non-critical
            // The window will use system default theme as fallback
            log::warn!(
                "Could not set window theme to Light (non-critical): {}. \
                Window will use system default theme as fallback.",
                e
            );
            // Note: We don't check the current theme here because:
            // 1. The theme() method may not be available on all platforms
            // 2. The fallback behavior is acceptable (system default)
            // 3. The application remains fully functional
        }
    }

    // Check connectivity asynchronously and navigate when ready
    let app_handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        log::info!("Checking network connectivity in background...");
        let is_online = check_network_connectivity_async().await;

        if let Some(window) = app_handle.get_webview_window("main") {
            if is_online {
                match APP_URL.parse() {
                    Ok(parsed_url) => {
                        log::info!("Connection detected, navigating to {}", APP_URL);
                        if let Err(e) = window.navigate(parsed_url) {
                            log::error!("Failed to navigate to {}: {}", APP_URL, e);
                        }
                    }
                    Err(e) => {
                        log::error!("URL parsing error for {}: {}", APP_URL, e);
                    }
                }
            } else {
                log::info!("No connection detected, keeping error page");
            }
        }
    });

    Ok(())
}

/// Gets the path to the update check cache file
#[cfg_attr(test, allow(dead_code))]
fn get_update_cache_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data directory: {}", e))
        .map(|mut path| {
            // Ensure directory exists
            if let Err(e) = fs::create_dir_all(&path) {
                log::warn!("Failed to create app data directory: {}", e);
            }
            path.push("update_check_cache.json");
            path
        })
}

/// Reads the last update check timestamp from cache
#[cfg_attr(test, allow(dead_code))]
fn read_last_update_check<R: Runtime>(app: &AppHandle<R>) -> Option<u64> {
    let cache_path = get_update_cache_path(app).ok()?;
    
    match fs::read_to_string(&cache_path) {
        Ok(content) => {
            #[derive(serde::Deserialize)]
            struct UpdateCache {
                last_check: u64,
            }
            
            match serde_json::from_str::<UpdateCache>(&content) {
                Ok(cache) => Some(cache.last_check),
                Err(e) => {
                    log::debug!("Failed to parse update cache: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            log::debug!("Failed to read update cache: {}", e);
            None
        }
    }
}

/// Writes the current timestamp to the update check cache
#[cfg_attr(test, allow(dead_code))]
fn write_last_update_check<R: Runtime>(app: &AppHandle<R>) {
    let cache_path = match get_update_cache_path(app) {
        Ok(path) => path,
        Err(e) => {
            log::warn!("Failed to get cache path: {}", e);
            return;
        }
    };
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    #[derive(serde::Serialize)]
    struct UpdateCache {
        last_check: u64,
    }
    
    let cache = UpdateCache { last_check: now };
    
    match serde_json::to_string_pretty(&cache) {
        Ok(json) => {
            if let Err(e) = fs::write(&cache_path, json) {
                log::warn!("Failed to write update cache: {}", e);
            } else {
                log::debug!("Updated check cache written to {:?}", cache_path);
            }
        }
        Err(e) => {
            log::warn!("Failed to serialize update cache: {}", e);
        }
    }
}

/// Checks if enough time has passed since the last update check
#[cfg_attr(test, allow(dead_code))]
fn should_check_for_updates<R: Runtime>(app: &AppHandle<R>) -> bool {
    let last_check = match read_last_update_check(app) {
        Some(timestamp) => timestamp,
        None => {
            log::debug!("No previous update check found, will check");
            return true;
        }
    };
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    let time_since_last_check = now.saturating_sub(last_check);
    
    if time_since_last_check >= UPDATE_CHECK_COOLDOWN_SECS {
        log::debug!(
            "Last update check was {} seconds ago (cooldown: {}), will check",
            time_since_last_check,
            UPDATE_CHECK_COOLDOWN_SECS
        );
        true
    } else {
        let remaining = UPDATE_CHECK_COOLDOWN_SECS - time_since_last_check;
        log::debug!(
            "Skipping update check (last check {} seconds ago, {} seconds remaining)",
            time_since_last_check,
            remaining
        );
        false
    }
}

/// Checks and installs available updates
/// 
/// Async function called automatically after startup.
/// Only checks if enough time has passed since the last check (24 hours by default).
/// Shows a French dialog asking if the user wants to update now or later.
/// If yes, downloads and installs silently, then exits for fast update.
async fn perform_update_check<R: Runtime>(app: &AppHandle<R>) {
    // Check if we should skip the update check based on cache
    if !should_check_for_updates(app) {
        return;
    }
    
    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(e) => {
            log::debug!("Unable to initialize update checker: {}", e);
            return;
        }
    };

    match updater.check().await {
        Ok(Some(update)) => {
            // Write cache immediately to prevent multiple dialogs
            write_last_update_check(app);
            
            let current_version = app.package_info().version.to_string();
            let dialog_message = format!(
                "Une nouvelle version est disponible, voulez-vous mettre à jour dès maintenant ?\n\n\
                Version actuelle : {}\n\
                Nouvelle version : {}",
                current_version,
                &update.version
            );

            let app_for_dialog = app.clone();
            let dialog_result = tauri::async_runtime::spawn_blocking(move || {
                app_for_dialog
                    .dialog()
                    .message(&dialog_message)
                    .title("Mise à jour disponible")
                    .buttons(tauri_plugin_dialog::MessageDialogButtons::YesNo)
                    .blocking_show()
            })
            .await;

            let should_update = match dialog_result {
                Ok(response) => response,
                Err(e) => {
                    log::error!("Unable to display update dialog: {}", e);
                    false
                }
            };

            if should_update {
                log::info!("User chose to update now, starting silent download and installation...");
                
                // Download and install silently (empty callbacks = no progress UI)
                // This makes the update as fast and quiet as possible
                match update.download_and_install(|_, _| {}, || {}).await {
                    Ok(_) => {
                        log::info!("Update installed successfully, exiting to complete installation...");
                        // Exit immediately for fastest update - no confirmation dialog needed
                        // The system will handle the restart automatically
                        std::process::exit(0);
                    }
                    Err(e) => {
                        log::error!("Update installation failed: {}", e);
                        // Show error dialog in French
                        let app_for_error = app.clone();
                        let error_message = format!(
                            "La mise à jour a échoué : {}\n\n\
                            Vous pouvez réessayer plus tard via le menu du système.",
                            e
                        );
                        let _ = tauri::async_runtime::spawn_blocking(move || {
                            app_for_error
                                .dialog()
                                .message(&error_message)
                                .title("Erreur de mise à jour")
                                .buttons(tauri_plugin_dialog::MessageDialogButtons::Ok)
                                .blocking_show();
                        })
                        .await;
                    }
                }
            } else {
                log::debug!("User chose to update later");
            }
        }
        Ok(None) => {
            // No update available, still write cache to avoid checking again soon
            write_last_update_check(app);
            log::debug!("No update available");
        }
        Err(e) => {
            log::debug!("Error checking for updates: {}", e);
            // Don't write cache on error, so we can retry sooner
        }
    }
}

// === GLOBAL RATE LIMITER ===

/// Global rate limiter instance for token operations
static RATE_LIMITER: OnceLock<RateLimiter> = OnceLock::new();

/// Gets or initializes the global rate limiter
fn get_rate_limiter() -> &'static RateLimiter {
    RATE_LIMITER.get_or_init(RateLimiter::new)
}

// === TAURI COMMANDS ===

/// Stores an authentication token securely
/// 
/// # Security Features
/// 
/// - Rate limiting: Maximum 10 requests per 60 seconds
/// - Input validation: Service, username, and token validation
/// - Audit logging: Logs operations without sensitive data
/// - Injection protection: Validates against null bytes and control characters
#[command]
async fn set_token(service: String, username: String, token: String) -> Result<(), String> {
    // Rate limiting check
    get_rate_limiter().check_rate_limit(
        "set_token",
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )?;

    // Enhanced input validation
    validate_service(&service)?;
    validate_token(&token)?;
    let normalized_username = normalize_username(&username)?;

    // Perform the operation
    let result = (|| -> Result<(), String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE_ID, &normalized_username)
            .map_err(|e| format!("Unable to create keyring entry: {}", e))?;
        
        entry
            .set_password(&token)
            .map_err(|e| format!("Token storage error: {:?}", e))
    })();

    // Audit logging (without logging the actual token)
    match &result {
        Ok(_) => {
            log_token_operation_audit("set_token", &normalized_username, true, None);
        }
        Err(e) => {
            log_token_operation_audit("set_token", &normalized_username, false, Some(e));
        }
    }

    result
}

/// Retrieves a stored authentication token
/// 
/// # Security Features
/// 
/// - Rate limiting: Maximum 10 requests per 60 seconds
/// - Input validation: Service and username validation
/// - Audit logging: Logs operations without sensitive data
/// - Injection protection: Validates against null bytes and control characters
#[command]
async fn get_token(service: String, username: String) -> Result<String, String> {
    // Rate limiting check
    get_rate_limiter().check_rate_limit(
        "get_token",
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )?;

    // Enhanced input validation
    validate_service(&service)?;
    let normalized_username = normalize_username(&username)?;

    // Perform the operation
    let result = (|| -> Result<String, String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE_ID, &normalized_username)
            .map_err(|e| format!("Unable to create keyring entry: {}", e))?;
        
        entry
            .get_password()
            .map_err(|e| format!("Token retrieval error: {:?}", e))
    })();

    // Audit logging (without logging the actual token)
    match &result {
        Ok(_) => {
            log_token_operation_audit("get_token", &normalized_username, true, None);
        }
        Err(e) => {
            log_token_operation_audit("get_token", &normalized_username, false, Some(e));
        }
    }

    result
}

/// Reloads the application by checking connectivity again
/// 
/// Used by the error page to allow the user to retry
#[command]
async fn reload_app(app: AppHandle) -> Result<(), String> {
    // Check connectivity asynchronously (using the new async function)
    let is_online = check_network_connectivity_async().await;

    if let Some(window) = app.get_webview_window("main") {
        if is_online {
            let url = APP_URL
                .parse()
                .map_err(|e| format!("URL parsing error: {}", e))?;
            window
                .navigate(url)
                .map_err(|e| format!("Navigation error: {}", e))?;
        } else {
            let error_url = LOCAL_ERROR_PAGE_URL
                .parse()
                .map_err(|e| format!("Local URL parsing error: {}", e))?;
            window
                .navigate(error_url)
                .map_err(|e| format!("Page reload error: {}", e))?;
        }
        Ok(())
    } else {
        Err("Main window not found".into())
    }
}

// === INTERFACE CONFIGURATION ===

/// Configures the system tray icon and its menu
fn setup_system_tray(app: &App) -> tauri::Result<()> {
    log::info!("Configuring system tray icon...");
    
    // Create menu items
    let open_item = MenuItemBuilder::with_id("open", "Ouvrir élulib").build(app)?;
    let settings_item = MenuItemBuilder::with_id("settings", "Paramètres").build(app)?;
    let update_check_item = MenuItemBuilder::with_id("check_updates", "Vérifier les mises à jour").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quitter").build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;
    
    // Build the menu
    let menu = MenuBuilder::new(app)
        .items(&[
            &open_item,
            &settings_item,
            &update_check_item,
            &separator,
            &quit_item,
        ])
        .build()?;

    log::info!("Creating system tray icon...");
    
    // Load the appropriate icon based on platform
    #[cfg(target_os = "windows")]
    let tray_icon = include_bytes!("../icons/icon.ico");
    #[cfg(not(target_os = "windows"))]
    let tray_icon = include_bytes!("../icons/32x32.png");
    
    let icon = Image::from_bytes(tray_icon)
        .map_err(|e| {
            log::error!("Unable to load system tray icon: {}", e);
            tauri::Error::from(e)
        })?;

    // Configure the icon with event handlers
    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("élulib")
        .icon(icon)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "open" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "settings" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.eval("window.location.href = 'https://app.elulib.com/settings'");
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "check_updates" => {
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    perform_update_check(&app_handle).await;
                });
            }
            "quit" => std::process::exit(0),
            _ => {}
        })
        .on_tray_icon_event(move |tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

// === MAIN ENTRY POINT ===

/// Main entry point of the application
/// 
/// Configures and starts the Tauri application with all its components.
/// This function never returns if the application starts successfully.
/// In case of build error, the error is logged and the application terminates.
pub fn run() {
    log::info!("Starting élulib application");
    
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_log::Builder::default().build())
        .setup(|app| {
            setup_system_tray(app)?;
            create_main_window(app)?;
            
            // Deferred update check
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(UPDATE_CHECK_DELAY_SECS)).await;
                perform_update_check(&app_handle).await;
            });
            
            // Periodic rate limiter cleanup to prevent memory growth
            // Run cleanup every hour to remove old entries
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600)); // 1 hour
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    get_rate_limiter().cleanup();
                    log::debug!("Rate limiter cleanup completed");
                }
            });
            
            Ok(())
        })
        .on_window_event(|app, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide instead of closing (typical desktop app behavior)
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            set_token,
            get_token,
            reload_app,
            notifications::show_notification
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            log::error!("Error starting élulib application: {}", e);
            eprintln!("Fatal error starting application: {}", e);
            std::process::exit(1);
        })
        .run(|_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { api, .. } => {
                api.prevent_exit();
            }
            _ => {}
        });
}


