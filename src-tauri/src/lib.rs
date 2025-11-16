//! Application desktop élulib - Wrapper Tauri pour l'application web
//!
//! Cette application fournit une interface native pour accéder à élulib.com
//! avec gestion hors-ligne, notifications et mises à jour automatiques.

mod notifications;

// === IMPORTS ORGANISÉS ===

// Core Tauri
use tauri::{
    command,
    menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem},
    tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState},
    window::Color,
    App, AppHandle, Manager, Runtime, TitleBarStyle, WebviewUrl, WebviewWindowBuilder,
    image::Image,
};

// Plugins Tauri
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_updater::UpdaterExt;

// Utilitaires réseau et asynchrones
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// === CONSTANTES DE CONFIGURATION ===

/// URL de l'application web principale
const APP_URL: &str = "https://app.elulib.com";

/// Hôte pour la vérification de connectivité
const CONNECTIVITY_HOST: &str = "app.elulib.com";

/// Port pour la vérification de connectivité
const CONNECTIVITY_PORT: u16 = 443;

/// Timeout pour la vérification de connectivité (secondes)
const CONNECTIVITY_TIMEOUT_SECS: u64 = 2;

/// Timeout de lecture/écriture pour les connexions TCP (secondes)
const TCP_RW_TIMEOUT_SECS: u64 = 1;

/// Titre de l'application
const APP_TITLE: &str = "élulib";

/// Dimensions de la fenêtre principale
const WINDOW_WIDTH: f64 = 1024.0;
const WINDOW_HEIGHT: f64 = 768.0;

/// Dimensions minimales de la fenêtre
const MIN_WINDOW_WIDTH: f64 = 480.0;
const MIN_WINDOW_HEIGHT: f64 = 600.0;

/// Délai avant vérification des mises à jour (secondes)
const UPDATE_CHECK_DELAY_SECS: u64 = 5;

/// URL du fallback local pour l'affichage hors ligne
const LOCAL_ERROR_PAGE_URL: &str = "http://localhost/connection-error.html";

/// Identifiant autorisé pour le stockage dans le trousseau
const KEYRING_SERVICE_ID: &str = "com.elulib.desktop";

/// Taille maximale autorisée pour le nom d'utilisateur du trousseau
const MAX_USERNAME_LENGTH: usize = 128;

/// Taille maximale autorisée pour un token stocké
const MAX_TOKEN_LENGTH: usize = 4096;

// === FONCTIONS UTILITAIRES ===

/// Vérifie la connectivité réseau de manière sécurisée
/// 
/// Utilise une approche synchrone compatible avec le setup de Tauri
/// avec résolution DNS et timeout pour éviter les blocages
fn check_network_connectivity() -> bool {
    match (CONNECTIVITY_HOST, CONNECTIVITY_PORT).to_socket_addrs() {
        Ok(addresses) => {
            for address in addresses {
                match TcpStream::connect_timeout(&address, Duration::from_secs(CONNECTIVITY_TIMEOUT_SECS)) {
                    Ok(stream) => {
                        // Configure les timeouts pour éviter les blocages
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(TCP_RW_TIMEOUT_SECS)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(TCP_RW_TIMEOUT_SECS)));
                        
                        log::debug!("Connexion TCP réussie à {} via {}", CONNECTIVITY_HOST, address);
                        return true;
                    }
                    Err(e) => {
                        log::debug!("Échec de connexion TCP à {} via {} - {}", CONNECTIVITY_HOST, address, e);
                    }
                }
            }

            log::debug!("Aucune adresse atteignable pour {}", CONNECTIVITY_HOST);
            false
        }
        Err(e) => {
            log::debug!("Échec de résolution DNS pour {}: {}", CONNECTIVITY_HOST, e);
            false
        }
    }
}

fn validate_service(service: &str) -> Result<(), String> {
    if service.trim() == KEYRING_SERVICE_ID {
        Ok(())
    } else {
        Err("Service non autorisé pour le trousseau".into())
    }
}

fn normalize_username(username: &str) -> Result<String, String> {
    let trimmed = username.trim();

    if trimmed.is_empty() {
        return Err("Nom d'utilisateur manquant".into());
    }

    if trimmed.len() > MAX_USERNAME_LENGTH {
        return Err("Nom d'utilisateur trop long".into());
    }

    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return Err(
            "Nom d'utilisateur invalide (caractères autorisés: a-z, 0-9, ._-@)".into(),
        );
    }

    Ok(trimmed.to_string())
}

fn validate_token(token: &str) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("Token vide ou manquant".into());
    }

    if token.len() > MAX_TOKEN_LENGTH {
        return Err("Token trop volumineux".into());
    }

    Ok(())
}

/// Crée la fenêtre principale selon l'état de la connexion
/// 
/// Si la connectivité est disponible, charge l'application web.
/// Sinon, affiche une page d'erreur locale avec possibilité de réessayer.
fn create_main_window(app: &App) -> tauri::Result<()> {
    let (url, _is_online) = if check_network_connectivity() {
        // Connexion disponible - charger l'application web
        match APP_URL.parse() {
            Ok(parsed_url) => {
                log::info!("Connexion détectée, chargement de {}", APP_URL);
                (WebviewUrl::External(parsed_url), true)
            }
            Err(e) => {
                log::error!("Erreur de parsing de l'URL {}: {}", APP_URL, e);
                // Fallback vers la page d'erreur locale via le protocole Tauri
                (
                    WebviewUrl::App("connection-error.html".into()),
                    false,
                )
            }
        }
    } else {
        // Pas de connexion - afficher la page d'erreur locale
        log::info!("Pas de connexion détectée, affichage de la page d'erreur locale");
        (
            WebviewUrl::App("connection-error.html".into()),
            false,
        )
    };

    log::info!("Chargement de l'URL : {:?}", url);

    WebviewWindowBuilder::new(app, "main", url)
        .title(APP_TITLE)
        .title_bar_style(TitleBarStyle::Visible)
        .background_color(Color(255, 255, 255, 255))
        .inner_size(WINDOW_WIDTH, WINDOW_HEIGHT)
        .min_inner_size(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
        .resizable(true)
        .initialization_script(include_str!("link_handler.js"))
        .decorations(true)
        .prevent_overflow()
        .build()?;

    Ok(())
}

/// Vérifie et installe les mises à jour disponibles
/// 
/// Fonction asynchrone appelée automatiquement après le démarrage
async fn perform_update_check<R: Runtime>(app: &AppHandle<R>) {
    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(e) => {
            log::debug!("Impossible d'initialiser le vérificateur de mises à jour: {}", e);
            return;
        }
    };

    match updater.check().await {
        Ok(Some(update)) => {
            let current_version = app.package_info().version.to_string();
            let dialog_message = format!(
                "Une nouvelle version est disponible. Voulez-vous l'installer maintenant ?\n\n\
                Version actuelle: {}\n\
                Nouvelle version: {}",
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
                    log::error!("Impossible d'afficher la boîte de dialogue de mise à jour: {}", e);
                    false
                }
            };

            if should_update {
                match update.download_and_install(|_, _| {}, || {}).await {
                    Ok(_) => {
                        log::info!("Mise à jour installée, fermeture de l'application pour finaliser l'installation...");
                        let app_after_install = app.clone();
                        if let Err(e) = tauri::async_runtime::spawn_blocking(move || {
                            app_after_install
                                .dialog()
                                .message("La mise à jour a été installée. L'application va redémarrer pour appliquer les changements.")
                                .title("Redémarrage nécessaire")
                                .blocking_show();
                        })
                        .await
                        {
                            log::error!("Impossible d'afficher la confirmation de redémarrage: {}", e);
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        log::error!("Échec de l'installation de la mise à jour: {}", e);
                    }
                }
            }
        }
        Ok(None) => log::debug!("Aucune mise à jour disponible"),
        Err(e) => log::debug!("Erreur lors de la vérification des mises à jour: {}", e),
    }
}

// === COMMANDES TAURI ===

/// Stocke un token d'authentification de manière sécurisée
#[command]
async fn set_token(service: String, username: String, token: String) -> Result<(), String> {
    validate_service(&service)?;
    validate_token(&token)?;
    let normalized_username = normalize_username(&username)?;

    let entry = keyring::Entry::new(KEYRING_SERVICE_ID, &normalized_username)
        .map_err(|e| format!("Impossible de créer l'entrée keyring: {}", e))?;
    
    entry
        .set_password(&token)
        .map_err(|e| format!("Erreur de stockage du token: {:?}", e))
}

/// Récupère un token d'authentification stocké
#[command]
async fn get_token(service: String, username: String) -> Result<String, String> {
    validate_service(&service)?;
    let normalized_username = normalize_username(&username)?;

    let entry = keyring::Entry::new(KEYRING_SERVICE_ID, &normalized_username)
        .map_err(|e| format!("Impossible de créer l'entrée keyring: {}", e))?;
    
    entry
        .get_password()
        .map_err(|e| format!("Erreur de récupération du token: {:?}", e))
}

/// Recharge l'application en vérifiant à nouveau la connectivité
/// 
/// Utilisée par la page d'erreur pour permettre à l'utilisateur de réessayer
#[command]
async fn reload_app(app: AppHandle) -> Result<(), String> {
    // Vérifie la connectivité de manière asynchrone
    let is_online = tauri::async_runtime::spawn_blocking(check_network_connectivity)
        .await
        .map_err(|e| format!("Erreur de vérification réseau: {}", e))?;

    if let Some(window) = app.get_webview_window("main") {
        if is_online {
            let url = APP_URL
                .parse()
                .map_err(|e| format!("Erreur de parsing URL: {}", e))?;
            window
                .navigate(url)
                .map_err(|e| format!("Erreur de navigation: {}", e))?;
        } else {
            let error_url = LOCAL_ERROR_PAGE_URL
                .parse()
                .map_err(|e| format!("Erreur de parsing URL locale: {}", e))?;
            window
                .navigate(error_url)
                .map_err(|e| format!("Erreur de rechargement de page: {}", e))?;
        }
        Ok(())
    } else {
        Err("Fenêtre principale introuvable".into())
    }
}

// === CONFIGURATION DE L'INTERFACE ===

/// Configure l'icône de la barre des tâches et son menu
fn setup_system_tray(app: &App) -> tauri::Result<()> {
    log::info!("Configuration de l'icône de la barre des tâches...");
    
    // Création des éléments du menu
    let open_item = MenuItemBuilder::with_id("open", "Ouvrir élulib").build(app)?;
    let settings_item = MenuItemBuilder::with_id("settings", "Paramètres").build(app)?;
    let update_check_item = MenuItemBuilder::with_id("check_updates", "Vérifier les mises à jour").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quitter élulib").build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;
    
    // Construction du menu
    let menu = MenuBuilder::new(app)
        .items(&[
            &open_item,
            &settings_item,
            &update_check_item,
            &separator,
            &quit_item,
        ])
        .build()?;

    log::info!("Création de l'icône de la barre des tâches...");
    
    // Chargement de l'icône appropriée selon la plateforme
    #[cfg(target_os = "windows")]
    let tray_icon = include_bytes!("../icons/icon.ico");
    #[cfg(not(target_os = "windows"))]
    let tray_icon = include_bytes!("../icons/32x32.png");
    
    let icon = Image::from_bytes(tray_icon)
        .expect("Impossible de charger l'icône de la barre des tâches");

    // Configuration de l'icône avec gestionnaires d'événements
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

// === POINT D'ENTRÉE PRINCIPAL ===

/// Point d'entrée principal de l'application
/// 
/// Configure et démarre l'application Tauri avec tous ses composants
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    log::info!("Démarrage de l'application élulib");
    
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
            
            // Vérification différée des mises à jour
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(UPDATE_CHECK_DELAY_SECS)).await;
                perform_update_check(&app_handle).await;
            });
            
            Ok(())
        })
        .on_window_event(|app, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Masquer au lieu de fermer (comportement classique des apps desktop)
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
        .expect("Erreur lors du démarrage de l'application élulib")
        .run(|_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { api, .. } => {
                api.prevent_exit();
            }
            _ => {}
        });
}
