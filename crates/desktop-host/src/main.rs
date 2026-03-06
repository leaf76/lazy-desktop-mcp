use anyhow::Result;
use desktop_core::{HostEnvelope, HostRequest, ToolError};
use desktop_host::{HostService, HostServiceConfig, SystemPlatformBackend};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .with_writer(std::io::stderr)
        .init();

    let config = HostServiceConfig::load()?;
    let mut service = HostService::new(SystemPlatformBackend, config).await?;
    let stdin = BufReader::new(io::stdin());
    let mut stdout = BufWriter::new(io::stdout());
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let envelope = match serde_json::from_str::<HostRequest>(&line) {
            Ok(request) => match service.handle(request).await {
                Ok(response) => HostEnvelope::Ok { response },
                Err(error) => HostEnvelope::Err { error },
            },
            Err(error) => HostEnvelope::Err {
                error: ToolError::validation(
                    format!("Invalid host request payload: {error}"),
                    "host-parse",
                ),
            },
        };

        stdout
            .write_all(serde_json::to_string(&envelope)?.as_bytes())
            .await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }

    Ok(())
}
