// src/download/mod.rs
//
// Motor de descargas en el PROCESO PADRE.
// Ya no toca tao/WebView directamente: delega el bypass a un subproceso
// (ver `worker.rs`) y descarga el CDN con reqwest, reportando progreso
// por un canal mpsc que la UI consumirá.

pub mod worker;

use reqwest::Client;
use std::error::Error as StdError;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::sync::mpsc;

/// Eventos emitidos por el motor hacia la UI.
#[derive(Debug, Clone)]
pub enum DownloadEvent {
    /// Se lanzó el subproceso para resolver la URL del CDN.
    ResolvingCdn,
    /// La descarga HTTP comenzó. `total` puede ser `None` si el servidor
    /// no envía `Content-Length`.
    Started { total: Option<u64> },
    /// Progreso incremental. `total` es `None` si desconocido.
    Progress { downloaded: u64, total: Option<u64> },
    /// Descarga completada con éxito.
    Finished { path: PathBuf },
    /// Cualquier fallo (red, subproceso, parseo, disco).
    Failed { error: String },
}

fn print_error_chain(prefix: &str, e: &dyn StdError) {
    eprintln!("{prefix}: {e}");
    let mut src = e.source();
    while let Some(s) = src {
        eprintln!("  causa: {s}");
        src = s.source();
    }
}

/// Lanza el subproceso worker y lee la línea JSON que contiene el CDN.
async fn resolve_cdn_url(buzz_url: String) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    let line = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let mut cmd = Command::new(&exe);
        cmd.arg("--download-worker")
            .arg(&buzz_url)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        // En release (GUI sin consola), evitamos que aparezca una ventana
        // de consola fugaz para el subproceso.
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd.spawn().map_err(|e| format!("spawn worker: {e}"))?;

        let stdout = child.stdout.take().ok_or("worker stdout missing")?;
        let mut reader = BufReader::new(stdout);
        let mut buf = String::new();
        let read = reader
            .read_line(&mut buf)
            .map_err(|e| format!("read worker stdout: {e}"))?;

        // El worker sale solo tras escribir la línea (tao llama a process::exit),
        // así que wait() regresa casi inmediato. Reapeamos para no dejar zombis.
        let _ = child.wait();

        if read == 0 {
            return Err("worker exited without emitting any data".into());
        }
        Ok(buf)
    })
    .await
    .map_err(|e| format!("join worker task: {e}"))??;

    let parsed: serde_json::Value = serde_json::from_str(line.trim())
        .map_err(|e| format!("parse worker JSON: {e} (line: {:?})", line.trim()))?;

    if parsed["status"].as_str() != Some("ok") {
        let msg = parsed["message"].as_str().unwrap_or("unknown worker error");
        return Err(msg.to_string());
    }

    let cdn_url = parsed["cdn_url"].as_str().ok_or("missing cdn_url")?;
    Ok(cdn_url.to_string())
}

/// Descarga `buzz_url` a `output_path`, emitiendo `DownloadEvent` por `tx`.
/// Pensado para ser invocado con `tokio::spawn` desde la UI.
pub async fn download_file_with_progress(
    buzz_url: &str,
    output_path: PathBuf,
    tx: mpsc::UnboundedSender<DownloadEvent>,
) {
    let _ = tx.send(DownloadEvent::ResolvingCdn);

    let cdn_url = match resolve_cdn_url(buzz_url.to_string()).await {
        Ok(u) => u,
        Err(e) => {
            let _ = tx.send(DownloadEvent::Failed { error: e });
            return;
        }
    };

    // Preview UTF-8-safe. `&str[..n]` panickea si `n` cae en una frontera
    // de bytes dentro de un codepoint multibyte (URLs con IRI crudas).
    let preview: String = cdn_url.chars().take(80).collect();
    println!("[Download] CDN resuelto: {preview}");

    let client = match Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(DownloadEvent::Failed {
                error: format!("build client: {e}"),
            });
            return;
        }
    };

    let mut response = match client.get(&cdn_url).send().await {
        Ok(r) => r,
        Err(e) => {
            print_error_chain("[Download] error en la petición HTTP", &e);
            let _ = tx.send(DownloadEvent::Failed {
                error: format!("http: {e}"),
            });
            return;
        }
    };

    if !response.status().is_success() {
        let _ = tx.send(DownloadEvent::Failed {
            error: format!("HTTP {}", response.status()),
        });
        return;
    }

    let total = response.content_length();
    let _ = tx.send(DownloadEvent::Started { total });

    let mut file = match tokio::fs::File::create(&output_path).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.send(DownloadEvent::Failed {
                error: format!("create file: {e}"),
            });
            return;
        }
    };

    let mut downloaded: u64 = 0;
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                print_error_chain("[Download] error leyendo chunk", &e);
                let _ = tx.send(DownloadEvent::Failed {
                    error: format!("chunk: {e}"),
                });
                return;
            }
        };
        if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await {
            let _ = tx.send(DownloadEvent::Failed {
                error: format!("write: {e}"),
            });
            return;
        }
        downloaded += chunk.len() as u64;
        let _ = tx.send(DownloadEvent::Progress { downloaded, total });
    }

    if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut file).await {
        let _ = tx.send(DownloadEvent::Failed {
            error: format!("flush: {e}"),
        });
        return;
    }

    let _ = tx.send(DownloadEvent::Finished { path: output_path });
}
