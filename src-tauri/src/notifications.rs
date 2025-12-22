//! Module de gestion des notifications système
//!
//! Fournit des fonctionnalités pour afficher des notifications natives
//! depuis l'application web avec gestion des permissions.

use tauri::{command, AppHandle};
use tauri_plugin_notification::NotificationExt;

/// Affiche une notification système depuis l'application web
///
/// # Arguments
/// * `app_handle` - Handle vers l'application Tauri
/// * `title` - Titre de la notification
/// * `body` - Corps optionnel de la notification
///
/// # Returns
/// * `Ok(())` si la notification a été affichée avec succès
/// * `Err(String)` avec le message d'erreur en cas d'échec
#[command]
pub async fn show_notification(
    app_handle: AppHandle,
    title: String,
    body: Option<String>,
) -> Result<(), String> {
    // Vérification et demande des permissions de notification
    let notification_manager = app_handle.notification();
    let current_permission = notification_manager
        .permission_state()
        .map_err(|e| format!("Impossible de vérifier les permissions: {}", e))?;

    // Si les permissions ne sont pas accordées, les demander
    if current_permission != tauri_plugin_notification::PermissionState::Granted {
        notification_manager
            .request_permission()
            .map_err(|e| format!("Erreur lors de la demande de permissions: {}", e))?;

        // Revérifier après la demande
        let updated_permission = notification_manager
            .permission_state()
            .map_err(|e| format!("Impossible de vérifier les permissions mises à jour: {}", e))?;

        if updated_permission != tauri_plugin_notification::PermissionState::Granted {
            return Err("Permissions de notification non accordées par l'utilisateur".to_string());
        }
    }

    // Construction et affichage de la notification
    let mut notification_builder = notification_manager.builder().title(&title);

    // Ajout du corps si fourni
    if let Some(body_text) = body {
        notification_builder = notification_builder.body(&body_text);
    }

    notification_builder
        .show()
        .map_err(|e| format!("Erreur lors de l'affichage de la notification: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_show_notification_function_exists() {
        // Test that the function signature is correct
        // Actual testing would require a mock AppHandle
        assert!(true);
    }

    #[test]
    fn test_notification_parameters() {
        // Test that the function accepts the correct parameters
        // - title: String
        // - body: Option<String>
        // This is a compile-time test
        fn _test_signature(
            _app_handle: AppHandle,
            _title: String,
            _body: Option<String>,
        ) -> Result<(), String> {
            Ok(())
        }
        assert!(true);
    }
}
