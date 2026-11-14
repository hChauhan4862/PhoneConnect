//! The PhoneConnect desktop shell.
//!
//! Built with `--features shell`. It is deliberately thin: the webview loads the
//! server-served UI at the configured URL, and the only native additions are the injected
//! host context, a tray, detached OS windows, OS notifications, and the loopback proxy
//! endpoints the endpoint manager owns. There is no second UI tree here.
//!
//! Run with `PHONECONNECT_SERVER_URL` set (default `http://127.0.0.1:8080`). The shell uses
//! the page's normal session cookies; it never embeds a server credential, and its transport
//! identity private half never leaves this process.

#[cfg(feature = "shell")]
mod shell {
    use std::sync::Arc;

    use phoneconnect_native::endpoints::{EndpointManager, OpenEndpointRequest};
    use phoneconnect_native::proxy::{LocalEndpoint, ProxyLimits};
    use phoneconnect_native::web_shell::{
        self, NotificationInput, TrayStatus, bridge_script, capability_origins, host_context,
        host_context_script, is_same_origin, resolve_route, route_window_label, tray_tooltip,
    };
    use phoneconnect_transport::IdentityKey;
    use tauri::ipc::CapabilityBuilder;
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use tauri::{AppHandle, Manager, RunEvent, State, WebviewUrl, WebviewWindowBuilder};
    use tauri_plugin_notification::NotificationExt;
    use url::Url;

    /// Label of the embedded window. Detached views use `web_shell::route_window_label`.
    const MAIN_WINDOW: &str = "main";
    /// Tray id, so a command can find the one tray the shell installs.
    const TRAY_ID: &str = "phoneconnect";
    /// Identifier of the runtime capability that grants the bridge commands to the server.
    const REMOTE_CAPABILITY: &str = "phoneconnect-remote";

    struct ShellState {
        server_url: Url,
        endpoints: Arc<EndpointManager>,
    }

    impl ShellState {
        /// The context to inject. `proxyCapabilities` is what the manager is serving *now*,
        /// never a placeholder: a window opened later sees the endpoints open at that moment,
        /// and the page refreshes the list through `localEndpoints()`.
        async fn host_context(&self) -> web_shell::NativeHostContext {
            host_context(&self.server_url, self.endpoints.endpoints().await)
        }
    }

    /// Opens a route the page asked for in a detached OS window.
    ///
    /// The route is re-resolved against the configured origin; a protocol-relative path or
    /// another host is rejected, so the page cannot use the shell to open an arbitrary site.
    #[tauri::command]
    async fn open_window(
        app: AppHandle,
        state: State<'_, ShellState>,
        route: String,
    ) -> Result<(), String> {
        let url = resolve_route(&state.server_url, &route).map_err(|error| error.to_string())?;
        let label = route_window_label(&route);
        if let Some(existing) = app.get_webview_window(&label) {
            existing.show().map_err(|error| error.to_string())?;
            existing.set_focus().map_err(|error| error.to_string())?;
            return Ok(());
        }
        let host_script = host_context_script(&state.host_context().await);
        let server = state.server_url.clone();
        let window = WebviewWindowBuilder::new(&app, &label, WebviewUrl::External(url))
            .title(format!("PhoneConnect \u{2014} {route}"))
            .inner_size(1100.0, 760.0)
            // A page that navigated off the server would inherit the bridge capabilities, so
            // the webview never leaves the configured origin.
            .on_navigation(move |url| is_same_origin(&server, url))
            .initialization_script(&host_script)
            .initialization_script(bridge_script())
            .build()
            .map_err(|error| error.to_string())?;
        window.set_focus().map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Updates the tray from the status the page reports.
    #[tauri::command]
    fn set_tray_status(app: AppHandle, status: TrayStatus) -> Result<(), String> {
        status.validate().map_err(|error| error.to_string())?;
        let tray = app
            .tray_by_id(TRAY_ID)
            .ok_or_else(|| "the tray is not installed".to_owned())?;
        tray.set_tooltip(Some(tray_tooltip(&status)))
            .map_err(|error| error.to_string())?;
        // A menu-bar title is useful on macOS and unsupported elsewhere.
        #[cfg(target_os = "macos")]
        {
            let title: String = status.label.chars().take(24).collect();
            tray.set_title(Some(title))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// Shows one OS notification. A refused notification is an error, not a silent success.
    #[tauri::command]
    fn notify(app: AppHandle, input: NotificationInput) -> Result<(), String> {
        input.validate().map_err(|error| error.to_string())?;
        app.notification()
            .builder()
            .title(input.title)
            .body(input.body)
            .show()
            .map_err(|error| error.to_string())
    }

    /// The identity public key the page pins when it creates a session for this shell.
    #[tauri::command]
    fn native_identity_key(state: State<'_, ShellState>) -> String {
        state.endpoints.identity_public_key()
    }

    /// Establishes (or reuses) a session for the device, binds a loopback port, and starts
    /// serving it. The returned URL is the endpoint the page can use.
    #[tauri::command]
    async fn open_endpoint(
        state: State<'_, ShellState>,
        request: OpenEndpointRequest,
    ) -> Result<LocalEndpoint, String> {
        state
            .endpoints
            .open(request)
            .await
            .map_err(|error| error.to_string())
    }

    /// Stops one endpoint; `false` means it was not open.
    #[tauri::command]
    async fn close_endpoint(
        state: State<'_, ShellState>,
        device_id: String,
        stream: String,
    ) -> Result<bool, String> {
        Ok(state.endpoints.close(&device_id, &stream).await)
    }

    /// The loopback endpoints currently exposed to the page.
    #[tauri::command]
    async fn local_endpoints(state: State<'_, ShellState>) -> Result<Vec<LocalEndpoint>, String> {
        Ok(state.endpoints.endpoints().await)
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let server_url = web_shell::configured_server_url()?;
        let identity = IdentityKey::generate()?;
        let endpoints = Arc::new(EndpointManager::new(identity, ProxyLimits::default()));
        let setup_endpoints = Arc::clone(&endpoints);
        let setup_server = server_url.clone();
        let window_url = server_url.clone();
        let navigation_url = server_url.clone();

        tauri::Builder::default()
            .plugin(tauri_plugin_notification::init())
            .manage(ShellState {
                server_url,
                endpoints,
            })
            .invoke_handler(tauri::generate_handler![
                open_window,
                set_tray_status,
                notify,
                native_identity_key,
                open_endpoint,
                close_endpoint,
                local_endpoints
            ])
            .setup(move |app| {
                install_tray(app.handle())?;
                install_remote_capability(app, &setup_server)?;
                let capabilities = tauri::async_runtime::block_on(setup_endpoints.endpoints());
                let context = host_context(&setup_server, capabilities);
                WebviewWindowBuilder::new(app, MAIN_WINDOW, WebviewUrl::External(window_url))
                    .title("PhoneConnect")
                    .inner_size(1100.0, 760.0)
                    .on_navigation(move |url| is_same_origin(&navigation_url, url))
                    .initialization_script(host_context_script(&context))
                    .initialization_script(bridge_script())
                    .build()?;
                Ok(())
            })
            .build(tauri::generate_context!())?
            // Closing the window hides the shell; the tray keeps the session alive. Quit from
            // the tray exits with an explicit code, which this event must not prevent.
            .run(|_app, event| {
                if let RunEvent::ExitRequested { code, api, .. } = event
                    && code.is_none()
                {
                    api.prevent_exit();
                }
            });
        Ok(())
    }

    /// Grants the seven bridge commands to exactly the configured origin.
    ///
    /// The static capability in `capabilities/default.json` carries no `remote` entry; this
    /// runtime capability is the only way a page gets IPC, so another origin — or a subframe
    /// on Windows, which receives initialization scripts too — cannot reach the commands.
    fn install_remote_capability(app: &mut tauri::App, server: &Url) -> tauri::Result<()> {
        let mut capability = CapabilityBuilder::new(REMOTE_CAPABILITY)
            .local(false)
            .windows(["*"])
            .permission("allow-open-window")
            .permission("allow-set-tray-status")
            .permission("allow-local-endpoints")
            .permission("allow-notify")
            .permission("allow-native-identity-key")
            .permission("allow-open-endpoint")
            .permission("allow-close-endpoint");
        for pattern in capability_origins(server) {
            capability = capability.remote(pattern);
        }
        app.add_capability(capability)
    }

    fn install_tray(app: &AppHandle) -> tauri::Result<()> {
        let show = MenuItem::with_id(app, "show", "Show PhoneConnect", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", "Quit PhoneConnect", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&show, &quit])?;
        let mut builder = TrayIconBuilder::with_id(TRAY_ID)
            .menu(&menu)
            .show_menu_on_left_click(false)
            .tooltip("PhoneConnect")
            .on_menu_event(|app, event| match event.id.as_ref() {
                "show" => show_main(app),
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show_main(tray.app_handle());
                }
            });
        if let Some(icon) = app.default_window_icon() {
            builder = builder.icon(icon.clone());
        }
        builder.build(app)?;
        Ok(())
    }

    fn show_main(app: &AppHandle) {
        if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

fn main() -> std::process::ExitCode {
    // A headless way to check the URL policy and the injected context, used by support and by
    // the build verification; it starts no webview.
    if std::env::args().any(|argument| argument == "--print-context") {
        let server = match phoneconnect_native::web_shell::configured_server_url() {
            Ok(server) => server,
            Err(error) => {
                eprintln!("phoneconnect-native: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };
        // Before any endpoint is opened; the live list is what a window injects.
        let context = phoneconnect_native::web_shell::host_context(&server, Vec::new());
        println!(
            "{}",
            serde_json::to_string_pretty(&context).expect("the host context is JSON")
        );
        return std::process::ExitCode::SUCCESS;
    }

    #[cfg(feature = "shell")]
    {
        match shell::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("phoneconnect-native: {error}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    #[cfg(not(feature = "shell"))]
    {
        eprintln!(
            "phoneconnect-native was built without the `shell` feature; \
             rebuild with `cargo build -p phoneconnect-native --features shell`"
        );
        std::process::ExitCode::FAILURE
    }
}
