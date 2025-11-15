async function reloadApp() {
    const button = document.querySelector('#button-reload');
    button.classList.add('is-disabled');
    const invoke =
        window.__TAURI__?.core?.invoke ?? window.__TAURI__?.invoke;

    if (!invoke) {
        throw new Error('API Tauri indisponible.');
    }

    await invoke('reload_app').then(() => {
        setTimeout(() => {
            button.classList.remove('is-disabled');
            window.location.reload();
        }, 1000);
    }).catch((error) => {
        setTimeout(() => {
            button.classList.remove('is-disabled');
        }, 1000);
        console.error('Erreur lors du rechargement:', error);
    });
}
