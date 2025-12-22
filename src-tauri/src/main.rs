//! Main entry point of the élulib application
//!
//! This file contains only the main entry point that delegates
//! initialization and execution to the main library.

// Prevent displaying an additional console window on Windows in release mode
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// Main function of the application
///
/// Delegates execution to the main library.
fn main() {
    // Delegate to the main application logic
    // If the application cannot start, run() will terminate with an error code
    elulib_desktop::run();
}
