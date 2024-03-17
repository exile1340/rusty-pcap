use rusty_pcap_lib::{api_server, Cli, read_config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simulate command-line arguments
    let args = Cli {
        config_file: Some("config.toml".to_string()),
        pcap_file: None,
        pcap_dir: None,
        timestamp: None,
        ip: vec![],
        src_ip: None,
        dest_ip: None,
        src_port: None,
        dest_port: None,
        port: vec![],
        log_level: Some("info".to_string()),
        no_timestamp: false,
        server: true,
    };

    // Read the configuration file
    let config = read_config(args.config_file.as_deref().unwrap())?;

    // Run the API server
    api_server::rocket(config).launch().await?;

    Ok(())
}