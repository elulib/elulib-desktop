(function () {
  const openInBrowser = (url) => {
    if (!url) {
      return;
    }

    const openUrl = window.__TAURI__?.opener?.openUrl;
    const invoke =
      window.__TAURI__?.core?.invoke ?? window.__TAURI__?.invoke;
    const openFallback = () => window.open(url, '_blank', 'noopener');

    const performOpen = openUrl
      ? () => openUrl(url)
      : invoke
        ? () =>
            invoke('plugin:opener|open_url', {
              url,
              with: 'default',
            })
        : null;

    if (!performOpen) {
      openFallback();
      return;
    }

    performOpen().catch((error) => {
      console.error('Impossible d’ouvrir l’URL dans le navigateur:', error);
      openFallback();
    });
  };

  const isLocalHost = (hostname) =>
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]';

  const isElulibHost = (hostname) =>
    hostname === 'elulib.com' || hostname.endsWith('.elulib.com');

  const shouldOpenExternally = (href) => {
    try {
      const targetUrl = new URL(href, window.location.href);
      const protocol = targetUrl.protocol.toLowerCase();

      if (protocol !== 'http:' && protocol !== 'https:') {
        return false;
      }

      const hostname = targetUrl.hostname.toLowerCase();

      if (targetUrl.origin === window.location.origin) {
        return false;
      }

      if (isLocalHost(hostname) || isElulibHost(hostname)) {
        return false;
      }

      return true;
    } catch (error) {
      return false;
    }
  };

  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[href]');
    if (!link) {
      return;
    }

    const href = link.getAttribute('href');
    if (!href) {
      return;
    }

    const requiresExternalOpen =
      link.target === '_blank' || shouldOpenExternally(href);

    if (requiresExternalOpen) {
      event.preventDefault();
      openInBrowser(href);
    }
  });

  const originalWindowOpen = window.open;
  window.open = function (url, target, features) {
    if (typeof url === 'string' && shouldOpenExternally(url)) {
      openInBrowser(url);
      return null;
    }
    return originalWindowOpen.call(window, url, target, features);
  };
})();

