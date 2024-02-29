// Import required modules
use std::fs;
use structopt::StructOpt;
use std;
use serde::{Deserialize, Serialize};
use crate::cli::{Cli, run_cli_search};
mod cli;
mod input_validation;
mod packet_parse;
mod write_pcap;
mod api_server;
mod search_pcap;
#[macro_use] extern crate rocket;

// Define a configuration struct for server settings
#[derive(FromForm, Deserialize, Serialize)]
pub struct Config {
    log_level: Option<String>,
    pcap_directory: Option<String>,
    output_directory: Option<String>,
    enable_server: bool,
    search_buffer: Option<String>,
}

// Function to read configuration from a file
fn read_config(config_path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_contents = fs::read_to_string(config_path)?; // Read the contents of the config file
    let config: Config = toml::from_str(&config_contents)?; // Parse the contents into a Config struct
    Ok(config)
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Parse command line arguments
    let args = Cli::from_args();

    // Read the configuration file
    let mut config = read_config(args.config_file.as_deref().unwrap_or("config.toml"))?;

    // Define a pcap filter based on the command line arguments and config file
    let pcap_filter = write_pcap::PcapFilter {
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