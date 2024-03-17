// Import required modules
use structopt::StructOpt;
use std;
use rusty_pcap_lib::{Cli, api_server, cli::run_cli_search, PcapFilter, read_config};

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Parse command line arguments
    let args = Cli::from_args();

    // Read the configuration file
    let mut config = read_config(args.config_file.as_deref().unwrap_or("config.toml"))?;

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
    let log_level = args.log_level
        .clone()
        .or(config.log_level.clone())
        .unwrap_or_else(|| "error".to_string());

    // Initialize the logger with the determined log level
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&log_level)).init();

    // Determine if the server should be started
    let run_server = args.server || config.enable_server;
    log::info!("Running in {} mode", if run_server { "Server" } else { "CLI" });

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