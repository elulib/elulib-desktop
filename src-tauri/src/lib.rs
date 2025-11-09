mod notifications;

use tauri::{
    AppHandle, Manager, Runtime, WebviewUrl, WebviewWindowBuilder,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState},
    image::Image,
};
use tauri::command;

#[cfg(target_os = "windows")]
const TRAY_ICON: &[u8] = include_bytes!("../icons/icon.ico");

#[cfg(not(target_os = "windows"))]
const TRAY_ICON: &[u8] = include_bytes!("../icons/32x32.png");
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_updater::UpdaterExt;

// No need for AppState with the new API

// Vérification des mises à jour disponibles (silencieuse en cas d'erreur ou pas de mise à jour)
async fn check_for_updates<R: Runtime>(app: &AppHandle<R>) {
    let updater = match app.updater() {
        Ok(u) => u,
        Err(e) => {
            log::debug!("Failed to get updater: {}", e);
            return;
        }
    };

    match updater.check().await {
        Ok(Some(update)) => {
            let should_update = app.dialog()
                .message(&format!(
                    "Une nouvelle version est disponible. Voulez-vous l'installer maintenant ?\n\nVersion actuelle: {}\nNouvelle version: {}",
                    env!("CARGO_PKG_VERSION"),
                    &update.version
                ))
                .title("Mise à jour disponible")
                .buttons(tauri_plugin_dialog::MessageDialogButtons::YesNo)
                .blocking_show();

            if should_update {
                if let Err(e) = update.download_and_install(|_, _| {}, || {}).await {
                    log::error!("Échec de l'installation de la mise à jour: {}", e);
                }
            }
        }
        Ok(None) => {
            log::debug!("No updates available");
        }
        Err(e) => {
            log::debug!("Erreur lors de la vérification des mises à jour: {}", e);
        }
    }
}

#[command]
async fn set_token(service: String, username: String, token: String) -> Result<(), String> {
    let entry = match keyring::Entry::new(&service, &username) {
        Ok(e) => e,
        Err(e) => return Err(format!("Failed to create keyring entry: {}", e)),
    };
    entry.set_password(&token).map_err(|e| format!("Keyring set error: {:?}", e))
}

#[command]
async fn get_token(service: String, username: String) -> Result<String, String> {
    let entry = match keyring::Entry::new(&service, &username) {
        Ok(e) => e,
        Err(e) => return Err(format!("Failed to create keyring entry: {}", e)),
    };
    entry.get_password().map_err(|e| format!("Keyring get error: {:?}", e))
}

// Création du menu système
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    log::info!("Setting up system tray...");
    
    // Create menu items using the new builder pattern
    let open = MenuItemBuilder::with_id("open", "Ouvrir élulib").build(app)?;
    let settings = MenuItemBuilder::with_id("settings", "Paramètres").build(app)?;
    let check_updates = MenuItemBuilder::with_id("check_updates", "Vérifier les mises à jour").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quitter").build(app)?;
    
    // Create menu with items using the new builder pattern
    let menu = MenuBuilder::new(app)
        .items(&[&open, &settings, &check_updates, &quit])
        .build()?;

    log::info!("Creating tray icon...");
    
    // Create tray icon with the menu and event handlers
    let tray_builder = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("élulib")
        .icon_as_template(false);
    
    // Use the embedded icon
    log::info!("Using embedded icon for the tray");
    let icon = Image::from_bytes(TRAY_ICON)
        .expect("Failed to load tray icon");
    let tray_builder = tray_builder.icon(icon);
    
    let _tray = tray_builder
        .on_menu_event(move |app, event| {
            match event.id().as_ref() {
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
                        check_for_updates(&app_handle).await;
                    });
                }
                "quit" => {
                    std::process::exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(move |tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    log::info!("Starting élulib application");
    
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_log::Builder::default().build())
        .plugin(notifications::init())
        .setup(|app| {
            setup_tray(app)?;
            if app.get_webview_window("main").is_none() {
                let _window = WebviewWindowBuilder::new(
                    app,
                    "main",
                    WebviewUrl::External("https://app.elulib.com".parse().unwrap())
                )
                .title("élulib")
                .inner_size(1024.0, 768.0)
                .min_inner_size(480.0, 600.0)
                .build()?;
            }
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                check_for_updates(&app_handle).await;
            });
            Ok(())
        })
        .on_window_event(|app, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![set_token, get_token])
        .build(tauri::generate_context!())
        .expect("Erreur lors du démarrage de l'application élulib")
        .run(|_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { api, .. } => {
                api.prevent_exit();
            }
            _ => {}
        });
}
