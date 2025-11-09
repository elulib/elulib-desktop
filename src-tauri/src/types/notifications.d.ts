declare namespace Tauri {
  interface InvokeArgs {
    title: string;
    body?: string;
  }

  function invoke(
    cmd: 'show_notification',
    args: InvokeArgs
  ): Promise<void>;
}

declare global {
  interface Window {
    __TAURI__: {
      invoke: typeof Tauri.invoke;
    };
  }
}

export {}
