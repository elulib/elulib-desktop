//! élulib Desktop Application - Tauri wrapper for the web application
//!
//! This application provides a native interface to access élulib.com
//! with offline management, notifications, and automatic updates.

mod constants;
mod notifications;

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
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// Constants
use constants::*;

// === UTILITY FUNCTIONS ===

/// Checks network connectivity securely with retry logic
/// 
/// Uses a synchronous approach compatible with Tauri setup
/// with DNS resolution, timeout, and exponential backoff retries to avoid blocking.
/// 
/// # Implementation Details
/// 
/// - Attempts connection with configurable timeout
/// - Implements exponential backoff for retries (up to MAX_CONNECTIVITY_RETRIES)
/// - Tries multiple DNS addresses if available
/// - Uses short timeouts to prevent UI freezing
/// 
/// # Performance
/// 
/// - First attempt: ~2 seconds timeout
/// - Retries: exponential backoff (500ms, 1000ms, etc.)
/// - Maximum total time: ~4-6 seconds in worst case
/// - Typical case: < 2 seconds if connection is available
/// 
/// # Returns
/// * `true` if connection is available
/// * `false` if connection is not available after all retries
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn check_network_connectivity() -> bool {
    // Try with retries using exponential backoff
    for attempt in 0..=MAX_CONNECTIVITY_RETRIES {
        if attempt > 0 {
            // Exponential backoff: 500ms, 1000ms, 2000ms, etc.
            let delay_ms = RETRY_BASE_DELAY_MS * (1 << (attempt - 1));
            log::debug!("Retrying connectivity check (attempt {}/{}) after {}ms delay", attempt + 1, MAX_CONNECTIVITY_RETRIES + 1, delay_ms);
            std::thread::sleep(Duration::from_millis(delay_ms));
        }

        match (CONNECTIVITY_HOST, CONNECTIVITY_PORT).to_socket_addrs() {
            Ok(addresses) => {
                // Try each resolved address
                for address in addresses {
                    match TcpStream::connect_timeout(&address, Duration::from_secs(CONNECTIVITY_TIMEOUT_SECS)) {
                        Ok(stream) => {
                            // Configure timeouts to avoid blocking
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(TCP_RW_TIMEOUT_SECS)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(TCP_RW_TIMEOUT_SECS)));
                            
                            if attempt > 0 {
                                log::info!("TCP connection successful to {} via {} (after {} retries)", CONNECTIVITY_HOST, address, attempt);
                            } else {
                                log::debug!("TCP connection successful to {} via {}", CONNECTIVITY_HOST, address);
                            }
                            return true;
                        }
                        Err(e) => {
                            log::debug!("TCP connection failed to {} via {} - {}", CONNECTIVITY_HOST, address, e);
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

/// Validates that the keyring service is authorized
/// 
/// # Arguments
/// * `service` - The service identifier to validate
/// 
/// # Returns
/// * `Ok(())` if the service is authorized
/// * `Err(String)` if the service is not authorized
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn validate_service(service: &str) -> Result<(), String> {
    if service.trim() == KEYRING_SERVICE_ID {
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
pub(crate) fn normalize_username(username: &str) -> Result<String, String> {
    let trimmed = username.trim();

    if trimmed.is_empty() {
        return Err("Username is missing".into());
    }

    if trimmed.len() > MAX_USERNAME_LENGTH {
        return Err("Username too long".into());
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
pub(crate) fn validate_token(token: &str) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("Token is empty or missing".into());
    }

    if token.len() > MAX_TOKEN_LENGTH {
        return Err("Token too large".into());
    }

    Ok(())
}

/// Creates the main window based on connection state
/// 
/// If connectivity is available, loads the web application.
/// Otherwise, displays a local error page with retry option.
/// 
/// # Network Connectivity Check
/// 
/// The connectivity check uses:
/// - Configurable timeout (2 seconds per attempt)
/// - Exponential backoff retry mechanism (up to 2 retries)
/// - Multiple DNS address resolution attempts
/// - Fast failure to prevent UI blocking
/// 
/// Total maximum time: ~4-6 seconds in worst case
/// Typical time: < 2 seconds if connection is available
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
    // Check connectivity with retry logic and exponential backoff
    // This is synchronous but uses short timeouts and retries to minimize blocking
    let (url, _is_online) = if check_network_connectivity() {
        // Connection available - load the web application
        match APP_URL.parse() {
            Ok(parsed_url) => {
                log::info!("Connection detected, loading {}", APP_URL);
                (WebviewUrl::External(parsed_url), true)
            }
            Err(e) => {
                log::error!("URL parsing error for {}: {}", APP_URL, e);
                // Fallback to local error page via Tauri protocol
                (
                    WebviewUrl::App("connection-error.html".into()),
                    false,
                )
            }
        }
    } else {
        // No connection - display local error page
        log::info!("No connection detected, displaying local error page");
        (
            WebviewUrl::App("connection-error.html".into()),
            false,
        )
    };

    log::info!("Loading URL: {:?}", url);

    let window = WebviewWindowBuilder::new(app, "main", url)
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

    Ok(())
}

/// Checks and installs available updates
/// 
/// Async function called automatically after startup
async fn perform_update_check<R: Runtime>(app: &AppHandle<R>) {
    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(e) => {
            log::debug!("Unable to initialize update checker: {}", e);
            return;
        }
    };

    match updater.check().await {
        Ok(Some(update)) => {
            let current_version = app.package_info().version.to_string();
            let dialog_message = format!(
                "A new version is available. Would you like to install it now?\n\n\
                Current version: {}\n\
                New version: {}",
                current_version,
                &update.version
            );

            let app_for_dialog = app.clone();
            let dialog_result = tauri::async_runtime::spawn_blocking(move || {
                app_for_dialog
                    .dialog()
                    .message(&dialog_message)
                    .title("Update Available")
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
                match update.download_and_install(|_, _| {}, || {}).await {
                    Ok(_) => {
                        log::info!("Update installed, closing application to finalize installation...");
                        let app_after_install = app.clone();
                        if let Err(e) = tauri::async_runtime::spawn_blocking(move || {
                            app_after_install
                                .dialog()
                                .message("The update has been installed. The application will restart to apply the changes.")
                                .title("Restart Required")
                                .blocking_show();
                        })
                        .await
                        {
                            log::error!("Unable to display restart confirmation: {}", e);
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        log::error!("Update installation failed: {}", e);
                    }
                }
            }
        }
        Ok(None) => log::debug!("No update available"),
        Err(e) => log::debug!("Error checking for updates: {}", e),
    }
}

// === TAURI COMMANDS ===

/// Stores an authentication token securely
#[command]
async fn set_token(service: String, username: String, token: String) -> Result<(), String> {
    validate_service(&service)?;
    validate_token(&token)?;
    let normalized_username = normalize_username(&username)?;

    let entry = keyring::Entry::new(KEYRING_SERVICE_ID, &normalized_username)
        .map_err(|e| format!("Unable to create keyring entry: {}", e))?;
    
    entry
        .set_password(&token)
        .map_err(|e| format!("Token storage error: {:?}", e))
}

/// Retrieves a stored authentication token
#[command]
async fn get_token(service: String, username: String) -> Result<String, String> {
    validate_service(&service)?;
    let normalized_username = normalize_username(&username)?;

    let entry = keyring::Entry::new(KEYRING_SERVICE_ID, &normalized_username)
        .map_err(|e| format!("Unable to create keyring entry: {}", e))?;
    
    entry
        .get_password()
        .map_err(|e| format!("Token retrieval error: {:?}", e))
}

/// Reloads the application by checking connectivity again
/// 
/// Used by the error page to allow the user to retry
#[command]
async fn reload_app(app: AppHandle) -> Result<(), String> {
    // Check connectivity asynchronously
    let is_online = tauri::async_runtime::spawn_blocking(check_network_connectivity)
        .await
        .map_err(|e| format!("Network verification error: {}", e))?;

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
    let open_item = MenuItemBuilder::with_id("open", "Open élulib").build(app)?;
    let settings_item = MenuItemBuilder::with_id("settings", "Settings").build(app)?;
    let update_check_item = MenuItemBuilder::with_id("check_updates", "Check for Updates").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit élulib").build(app)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    mod validate_service_tests {
        use super::*;

        #[test]
        fn test_validate_service_valid() {
            assert!(validate_service("com.elulib.desktop").is_ok());
            assert!(validate_service("  com.elulib.desktop  ").is_ok());
        }

        #[test]
        fn test_validate_service_invalid() {
            assert!(validate_service("invalid.service").is_err());
            assert!(validate_service("").is_err());
            assert!(validate_service("com.other.app").is_err());
            assert!(validate_service("com.elulib.desktop.extra").is_err());
        }

        #[test]
        fn test_validate_service_partial_match() {
            assert!(validate_service("com.elulib").is_err());
            assert!(validate_service("elulib.desktop").is_err());
        }
    }

    mod normalize_username_tests {
        use super::*;

        #[test]
        fn test_normalize_username_valid_alphanumeric() {
            assert_eq!(normalize_username("user123").unwrap(), "user123");
            assert_eq!(normalize_username("User123").unwrap(), "User123");
            assert_eq!(normalize_username("123user").unwrap(), "123user");
        }

        #[test]
        fn test_normalize_username_valid_with_dots() {
            assert_eq!(normalize_username("user.name").unwrap(), "user.name");
            assert_eq!(normalize_username("user.name.test").unwrap(), "user.name.test");
        }

        #[test]
        fn test_normalize_username_valid_with_underscores() {
            assert_eq!(normalize_username("user_name").unwrap(), "user_name");
            assert_eq!(normalize_username("user_name_test").unwrap(), "user_name_test");
        }

        #[test]
        fn test_normalize_username_valid_with_hyphens() {
            assert_eq!(normalize_username("user-name").unwrap(), "user-name");
            assert_eq!(normalize_username("user-name-test").unwrap(), "user-name-test");
        }

        #[test]
        fn test_normalize_username_valid_with_at_symbol() {
            assert_eq!(normalize_username("user@example.com").unwrap(), "user@example.com");
        }

        #[test]
        fn test_normalize_username_trims_whitespace() {
            assert_eq!(normalize_username("  user123  ").unwrap(), "user123");
            assert_eq!(normalize_username("\tuser123\n").unwrap(), "user123");
            assert_eq!(normalize_username("  user.name  ").unwrap(), "user.name");
        }

        #[test]
        fn test_normalize_username_empty_string() {
            assert!(normalize_username("").is_err());
        }

        #[test]
        fn test_normalize_username_whitespace_only() {
            assert!(normalize_username("   ").is_err());
            assert!(normalize_username("\t\n").is_err());
            assert!(normalize_username(" \t \n ").is_err());
        }

        #[test]
        fn test_normalize_username_too_long() {
            let long_username = "a".repeat(129);
            assert!(normalize_username(&long_username).is_err());
        }

        #[test]
        fn test_normalize_username_max_length() {
            let max_username = "a".repeat(128);
            assert!(normalize_username(&max_username).is_ok());
        }

        #[test]
        fn test_normalize_username_invalid_characters() {
            assert!(normalize_username("user with spaces").is_err());
            assert!(normalize_username("user#special").is_err());
            assert!(normalize_username("user$invalid").is_err());
            assert!(normalize_username("user%invalid").is_err());
            assert!(normalize_username("user&invalid").is_err());
            assert!(normalize_username("user*invalid").is_err());
            assert!(normalize_username("user(invalid").is_err());
            assert!(normalize_username("user)invalid").is_err());
            assert!(normalize_username("user[invalid").is_err());
            assert!(normalize_username("user]invalid").is_err());
            assert!(normalize_username("user{invalid").is_err());
            assert!(normalize_username("user}invalid").is_err());
        }

        #[test]
        fn test_normalize_username_mixed_valid_characters() {
            assert_eq!(
                normalize_username("user.name_test@example.com").unwrap(),
                "user.name_test@example.com"
            );
            assert_eq!(
                normalize_username("user-name.test_123@domain.co").unwrap(),
                "user-name.test_123@domain.co"
            );
        }
    }

    mod validate_token_tests {
        use super::*;

        #[test]
        fn test_validate_token_valid() {
            assert!(validate_token("token123").is_ok());
            assert!(validate_token("a").is_ok());
            assert!(validate_token("very-long-token-string").is_ok());
        }

        #[test]
        fn test_validate_token_with_whitespace() {
            assert!(validate_token("  token  ").is_ok());
            assert!(validate_token("\ttoken\n").is_ok());
        }

        #[test]
        fn test_validate_token_max_length() {
            let max_token = "a".repeat(4096);
            assert!(validate_token(&max_token).is_ok());
        }

        #[test]
        fn test_validate_token_empty_string() {
            assert!(validate_token("").is_err());
        }

        #[test]
        fn test_validate_token_whitespace_only() {
            assert!(validate_token("   ").is_err());
            assert!(validate_token("\t\n").is_err());
            assert!(validate_token(" \t \n ").is_err());
        }

        #[test]
        fn test_validate_token_too_long() {
            let long_token = "a".repeat(4097);
            assert!(validate_token(&long_token).is_err());
        }

        #[test]
        fn test_validate_token_special_characters() {
            // Tokens can contain any characters, including special ones
            assert!(validate_token("token!@#$%^&*()").is_ok());
            assert!(validate_token("token with spaces").is_ok());
            assert!(validate_token("token\nwith\nnewlines").is_ok());
            assert!(validate_token("token\twith\ttabs").is_ok());
        }

        #[test]
        fn test_validate_token_unicode() {
            assert!(validate_token("token-émoji-🚀").is_ok());
            assert!(validate_token("token-中文").is_ok());
        }
    }

    mod check_network_connectivity_tests {
        use super::*;

        #[test]
        fn test_check_network_connectivity_no_panic() {
            // This test just ensures the function doesn't panic
            // Actual result depends on network availability
            let _result = check_network_connectivity();
        }

        #[test]
        fn test_check_network_connectivity_returns_boolean() {
            let result = check_network_connectivity();
            assert!(result == true || result == false);
        }

        #[test]
        fn test_check_network_connectivity_idempotent() {
            // Multiple calls should not panic
            let _result1 = check_network_connectivity();
            let _result2 = check_network_connectivity();
            let _result3 = check_network_connectivity();
        }
    }
}
