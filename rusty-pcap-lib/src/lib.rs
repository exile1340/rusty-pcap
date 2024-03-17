// lib.rs
pub mod cli;
pub mod write_pcap;
pub mod api_server;
pub mod input_validation;
pub mod packet_parse;
pub mod search_pcap;
use serde::{Deserialize, Serialize};
use rocket::FromForm;
use structopt::StructOpt;
use std::fs;

// Define a configuration struct for server settings
#[derive(FromForm, Deserialize, Serialize)]
pub struct Config {
    pub log_level: Option<String>,
    pub pcap_directory: Option<String>,
    pub output_directory: Option<String>,
    pub enable_server: bool,
    pub search_buffer: Option<String>,
}

// Define a struct PcapFilter with the derive traits for form handling, serialization, deserialization, comparison, and debugging
#[derive(FromForm, Deserialize, Serialize, PartialEq, Debug)]
pub struct PcapFilter {
    pub ip: Option<Vec<std::net::IpAddr>>,
    pub port: Option<Vec<u16>>,
    pub src_ip: Option<std::net::IpAddr>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<std::net::IpAddr>,
    pub dest_port: Option<u16>,
    pub timestamp: Option<String>,
    pub buffer: Option<String>,
}

#[derive(StructOpt)]
pub struct Cli {
    #[structopt(help = "Config file", short = "c", long = "config")]
    pub config_file: Option<String>,

    #[structopt(help = "PCAP file to parse", short = "f", long = "file", conflicts_with = "pcap_dir")]
    pub pcap_file: Option<std::path::PathBuf>,

    #[structopt(help = "Directory for Suricata PCAP files", short = "l", long = "pcap_dir", conflicts_with = "pcap_file")]
    pub pcap_dir: Option<String>,

    #[structopt(help = "Timestamp of the flow", long = "ts", conflicts_with = "no_timestamp")]
    pub timestamp: Option<String>,

    #[structopt(help = "IP to filter on", long = "ip", multiple = true)]
    pub ip: Vec<std::net::IpAddr>,

    #[structopt(help = "Source IP to filter on", long = "src_ip")]
    pub src_ip: Option<std::net::IpAddr>,

    #[structopt(help = "Destination IP to filter on", long = "dest_ip")]
    pub dest_ip: Option<std::net::IpAddr>,

    #[structopt(help = "Source port to filter on", long = "src_port")]
    pub src_port: Option<u16>,

    #[structopt(help = "Destination port to filter on", long = "dest_port")]
    pub dest_port: Option<u16>,

    #[structopt(help = "Port to filter on", long = "port", multiple = true)]
    pub port: Vec<u16>,

    #[structopt(help = "Log level (e.g., debug, info, warn, error)", long = "log-level")]
    pub log_level: Option<String>,

    #[structopt(help = "If no timestamp is given, use this flag to search all pcap files", long = "no-timestamp")]
    pub no_timestamp: bool,

    #[structopt(help = "Run API server", long = "server")]
    pub server: bool,
}
// Function to read configuration from a file
pub fn read_config(config_path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_contents = fs::read_to_string(config_path)?; // Read the contents of the config file
    let config: Config = toml::from_str(&config_contents)?; // Parse the contents into a Config struct
    Ok(config)
}