//! System notification management module
//!
//! Provides functionality to display native notifications
//! from the web application with permission management.

use tauri::{command, AppHandle};
use tauri_plugin_notification::NotificationExt;

/// Displays a system notification from the web application
///
/// # Arguments
/// * `app_handle` - Handle to the Tauri application
/// * `title` - Notification title
/// * `body` - Optional notification body
///
/// # Returns
/// * `Ok(())` if the notification was displayed successfully
/// * `Err(String)` with the error message on failure
#[command]
pub async fn show_notification(
    app_handle: AppHandle,
    title: String,
    body: Option<String>,
) -> Result<(), String> {
    // Check and request notification permissions
    let notification_manager = app_handle.notification();
    let current_permission = notification_manager
        .permission_state()
        .map_err(|e| format!("Unable to check permissions: {}", e))?;

    // If permissions are not granted, request them
    if current_permission != tauri_plugin_notification::PermissionState::Granted {
        notification_manager
            .request_permission()
            .map_err(|e| format!("Error requesting permissions: {}", e))?;

        // Re-check after request
        let updated_permission = notification_manager
            .permission_state()
            .map_err(|e| format!("Unable to check updated permissions: {}", e))?;

        if updated_permission != tauri_plugin_notification::PermissionState::Granted {
            return Err("Notification permissions not granted by user".to_string());
        }
    }

    // Build and display the notification
    let mut notification_builder = notification_manager.builder().title(&title);

    // Add body if provided
    if let Some(body_text) = body {
        notification_builder = notification_builder.body(&body_text);
    }

    notification_builder
        .show()
        .map_err(|e| format!("Error displaying notification: {}", e))?;

    Ok(())
}

