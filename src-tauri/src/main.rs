//! Point d'entrée principal de l'application élulib
//!
//! Ce fichier contient uniquement le point d'entrée principal qui délègue
//! l'initialisation et l'exécution à la bibliothèque principale.

/// Fonction principale de l'application
///
/// Désactive la fenêtre de console sur Windows en mode release
/// et délègue l'exécution à la bibliothèque principale.
fn main() {
    // Prévention de l'affichage d'une console supplémentaire sur Windows
    #[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
    // Délégation à la logique principale de l'application
    elulib_desktop::run();
}
