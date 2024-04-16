// Import required modules
use rusty_pcap_lib::{api_server, cli::run_cli_search, read_config, Cli, PcapFilter};
use structopt::StructOpt;

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args = Cli::from_args();

    // Read the configuration file
    let mut config = read_config(args.config_file.as_deref().unwrap_or("config.toml"))?;

    // If a local config file is present overwrite the config values
    if let Ok(local_settings) = read_config("config.local.toml") {
        if let Some(local_server_settings) = local_settings.server {
            if let Some(ref mut server_config) = config.server {
                // Update address
                if let Some(address) = local_server_settings.address {
                    server_config.address = Some(address);
                }
                // Update port
                if let Some(port) = local_server_settings.port {
                    server_config.port = Some(port);
                }
                // Update cert
                if let Some(cert) = local_server_settings.cert {
                    server_config.cert = Some(cert);
                }
                // Update key
                if let Some(key) = local_server_settings.key {
                    server_config.key = Some(key);
                }
            }
        }
    }
    // Define a pcap filter based on the command line arguments and config file
    let pcap_filter = PcapFilter {
        ip: Some(args.ip.clone()),
        port: Some(args.port.clone()),
        src_ip: args.src_ip,
        src_port: args.src_port,
        dest_ip: args.dest_ip,
        dest_port: args.dest_port,
        timestamp: args.timestamp.clone(),
        buffer: config.search_buffer.clone(),
    };

    // Determine log level from command line arguments or configuration file
    let log_level = args
        .log_level
        .clone()
        .or(config.log_level.clone())
        .unwrap_or_else(|| "error".to_string());
    config.log_level = Some(log_level.clone());

    // Initialize the logger with the determined log level
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&log_level)).init();

    log::info!("Logging level set to {}", log_level);

    // Determine if the server should be started
    let run_server = args.server || config.enable_server.unwrap();
    log::info!(
        "Running in {} mode",
        if run_server { "Server" } else { "CLI" }
    );

    // If no pcap_directory was specified in the config file, try to use the directory specified in the command line arguments
    // If no directory was specified at all, exit the program with an error
    if config.pcap_directory.is_none() {
        config.pcap_directory = match args.pcap_dir.clone() {
            Some(dir) => Some(dir),
            None => {
                log::error!("Pcap directory is not set, update config.toml file or include --pcap-dir at runtime");
                std::process::exit(1);
            }
        };
    }

    log::debug!("Config: \n{}", &config);

    // If the server is not enabled, run a CLI search
    // If the server is enabled, start the API server
    if !run_server {
        run_cli_search(pcap_filter, args, &config)?;
    } else {
        log::info!("Starting API server...");
        api_server::rocket(config).launch().await?;
    }

    Ok(())
}
