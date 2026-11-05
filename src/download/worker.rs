// src/download/worker.rs
//
// Subproceso hijo que aísla el motor WebView2 en su propio event loop.
// Se invoca como: buzzheavier-client.exe --download-worker <buzz_url>
// Emite por stdout UNA línea JSON:
//   {"status":"ok","cdn_url":"https://ts.buzzheavier.com/..."}
//   {"status":"error","message":"..."}

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use wry::WebViewBuilder;

#[derive(Debug)]
enum WorkerEvent {
    Done,
}

pub fn run_worker(buzz_url: &str) -> ! {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = buzz_url;
        eprintln!("worker: only supported on Windows");
        std::process::exit(1)
    }

    #[cfg(target_os = "windows")]
    {
        let event_loop = EventLoopBuilder::<WorkerEvent>::with_user_event().build();
        let proxy = event_loop.create_proxy();

        let window = tao::window::WindowBuilder::new()
            .with_visible(false)
            .build(&event_loop)
            .expect("worker: failed to create window");

        let done = Arc::new(AtomicBool::new(false));
        let done_handler = done.clone();
        let done_timeout = done.clone();

        let _webview = WebViewBuilder::new(&window)
            .with_url(buzz_url)
            .with_initialization_script(
                r"
                window.addEventListener('load', () => {
                    const btn = document.querySelector('.download-btn');
                    if (btn) {
                        const hxGet = btn.getAttribute('hx-get');
                        window.location.href = hxGet;
                    }
                });
                ",
            )
            .with_download_started_handler(move |uri, _path| {
                done_handler.store(true, Ordering::SeqCst);
                let line = serde_json::json!({"status": "ok", "cdn_url": uri}).to_string();
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                let _ = writeln!(lock, "{line}");
                let _ = lock.flush();
                drop(lock);
                let _ = proxy.send_event(WorkerEvent::Done);
                false // Cancelamos la descarga nativa del WebView
            })
            .build()
            .expect("worker: failed to build webview");

        // Timeout de seguridad: si en 30s no se intercepta nada, emitimos error.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(30));
            if !done_timeout.load(Ordering::SeqCst) {
                let line = serde_json::json!({
                    "status": "error",
                    "message": "worker timeout after 30s (Cloudflare not bypassed?)"
                })
                .to_string();
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                let _ = writeln!(lock, "{line}");
                let _ = lock.flush();
                drop(lock);
                std::process::exit(2);
            }
        });

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            if let tao::event::Event::UserEvent(WorkerEvent::Done) = event {
                *control_flow = ControlFlow::Exit;
            }
        })
    }
}
