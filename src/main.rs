#![allow(dead_code)] // api/crypto aún sin cablear (iteración 3). download se usa en --test-download.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod crypto;
mod db;
mod download;
mod ui;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // ── Worker aislado para bypass Cloudflare (mismo binario, otro proceso) ──
    if args.len() >= 3 && args[1] == "--download-worker" {
        download::worker::run_worker(&args[2]);
    }

    // ── Flag oculto: regression test del motor de Fase 3 ──
    if args.len() >= 2 && args[1] == "--test-download" {
        run_test_download();
        return Ok(());
    }

    // ── Inicializar DB antes de la GUI ──
    let (db, db_error) = match init_db() {
        Ok(d) => (Some(d), None),
        Err(e) => (None, Some(e)),
    };

    // ── GUI normal ──
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BuzzHeavier Client",
        native_options,
        Box::new(move |cc| {
            setup_custom_style(&cc.egui_ctx);
            Box::new(ui::BuzzHeavierApp::new(cc, db, db_error))
        }),
    )
}

fn setup_custom_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    // Paleta de colores Modern Dark
    let bg_color = egui::Color32::from_rgb(30, 30, 30);
    let panel_color = egui::Color32::from_rgb(37, 37, 38);
    let accent_color = egui::Color32::from_rgb(77, 107, 254); // Azul moderno
    let text_color = egui::Color32::from_rgb(224, 224, 224);

    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = panel_color;
    style.visuals.window_fill = bg_color;
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(20, 20, 20);
    style.visuals.override_text_color = Some(text_color);

    // Colores de acento
    style.visuals.widgets.active.bg_fill = accent_color;
    style.visuals.widgets.hovered.bg_fill = accent_color.linear_multiply(0.8);
    style.visuals.selection.bg_fill = accent_color.linear_multiply(0.5);
    style.visuals.hyperlink_color = accent_color;

    // Bordes redondeados modernos
    let rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.noninteractive.rounding = rounding;
    style.visuals.widgets.inactive.rounding = rounding;
    style.visuals.widgets.hovered.rounding = rounding;
    style.visuals.widgets.active.rounding = rounding;
    style.visuals.window_rounding = egui::Rounding::same(10.0);

    // Espaciados
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);

    ctx.set_style(style);
}

fn init_db() -> Result<db::Database, String> {
    let dir = data_dir().map_err(|e| format!("data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create dir: {e}"))?;
    let path = dir.join("buzzheavier.db");
    db::Database::open(&path).map_err(|e| format!("db open: {e}"))
}

fn data_dir() -> std::io::Result<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("APPDATA")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "APPDATA not set"))?;
        Ok(std::path::PathBuf::from(base).join("BuzzHeavier-Client"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local").join("share"))
            })
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no data dir"))?;
        Ok(base.join("BuzzHeavier-Client"))
    }
}

fn run_test_download() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            download::download_file_with_progress(
                "https://buzzheavier.com/m1kfqwiu6vzx",
                std::path::PathBuf::from("archivo_descargado_rust.txt"),
                tx,
            )
            .await;
        });

        while let Some(evt) = rx.recv().await {
            match evt {
                download::DownloadEvent::Finished { path } => {
                    println!("[Test] ✓ Descarga completada: {path:?}");
                    break;
                }
                download::DownloadEvent::Failed { error } => {
                    eprintln!("[Test] ✗ Falló: {error}");
                    break;
                }
                _ => {}
            }
        }
    });
}
