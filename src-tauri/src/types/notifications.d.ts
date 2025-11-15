type ShowNotificationArgs = {
  title: string;
  body?: string;
};

type ShowNotificationInvoke = (
  cmd: 'show_notification',
  args: ShowNotificationArgs
) => Promise<void>;

type TauriCoreApi = {
  invoke: ShowNotificationInvoke;
};

type TauriBridge = {
  core?: TauriCoreApi;
  invoke?: ShowNotificationInvoke;
};

declare global {
  interface Window {
    __TAURI__?: TauriBridge;
  }
}

export {};
