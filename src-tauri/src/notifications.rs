use tauri::State;
use tauri_plugin_notification::NotificationExt;

// Command to show a notification from the webview
#[tauri::command]
pub async fn show_notification(
    app_handle: State<'_, tauri::AppHandle>,
    title: String,
    body: Option<String>,
) -> Result<(), String> {
    let app_handle = app_handle.inner().clone();
    // Check if we have permission
    let permission_state = app_handle.notification().permission_state()
        .map_err(|e| format!("Failed to check notification permission: {}", e))?;
    
    if permission_state != tauri_plugin_notification::PermissionState::Granted {
        // Request permission if we don't have it
        app_handle.notification().request_permission()
            .map_err(|e| format!("Failed to request notification permission: {}", e))?;
        
        // Check again after requesting
        let permission_state = app_handle.notification().permission_state()
            .map_err(|e| format!("Failed to verify notification permission: {}", e))?;
            
        if permission_state != tauri_plugin_notification::PermissionState::Granted {
            return Err("Notification permission not granted".to_string());
        }
    }

    // Send the notification
    app_handle.notification()
        .builder()
        .title(&title)
        .body(body.as_deref().unwrap_or_default())
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    Ok(())
}

// Setup function to register notification handlers
pub fn init<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::<R, ()>::new("notifications")
        .invoke_handler(tauri::generate_handler![show_notification])
        .build()
}
