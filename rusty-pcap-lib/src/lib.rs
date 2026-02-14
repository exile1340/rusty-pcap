/*
 * This file is part of rusty-pcap.
 *
 * rusty-pcap is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * rusty-pcap is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * rusty-pcap. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * This file contains the code that handles rusty pcap lib setup.
 */

// Import necessary libraries and modules
#![allow(clippy::blocks_in_conditions)]
pub mod api_server;
pub mod cli;
pub mod input_validation;
pub mod packet_parse;
pub mod pcap_agent;
pub mod search_pcap;
pub mod write_pcap;
use rocket::FromForm;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use clap::Parser;

// Define a configuration struct for server settings
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub log_level: Option<String>,
    pub pcap_directory: Option<String>,
    pub output_directory: Option<String>,
    pub enable_server: Option<bool>,
    pub search_buffer: Option<String>,
    pub server: Option<RocketConfig>,
    pub enable_cors: bool,
    pub pcap_agent: Option<pcap_agent::PcapAgentConfig>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            log_level: Some("warning".to_string()),
            pcap_directory: None,
            output_directory: Some("output".to_string()),
            enable_server: Some(false),
            search_buffer: Some("30s".to_string()),
            server: None,
            enable_cors: false,
            pcap_agent: None,
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "Log Level: {}",
            self.log_level.as_deref().unwrap_or("None")
        )?;
        writeln!(
            f,
            "Pcap Directory: {}",
            self.pcap_directory.as_deref().unwrap_or("None")
        )?;
        writeln!(
            f,
            "Output Directory: {}",
            self.output_directory.as_deref().unwrap_or("None")
        )?;
        writeln!(f, "Server: {}", self.enable_server.unwrap_or(false))?;
        writeln!(
            f,
            "Search Buffer: {}",
            self.search_buffer.as_deref().unwrap_or("None")
        )?;
        writeln!(f, "Server Settings: {:?}", self.server)?;
        writeln!(f, "Enable CORS: {}", self.enable_cors)?;
        writeln!(f, "Pcap Agent: {:?}", self.pcap_agent)?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RocketConfig {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub key: Option<String>,
    pub cert: Option<String>,
}

// Define a struct PcapFilter with the derive traits for form handling, serialization, deserialization, comparison, and debugging
#[derive(Deserialize, Serialize, PartialEq, Debug, FromForm, Clone)]
pub struct PcapFilter {
    pub port: Option<Vec<u16>>,
    pub src_ip: Option<std::net::IpAddr>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<std::net::IpAddr>,
    pub dest_port: Option<u16>,
    pub timestamp: Option<String>,
    pub buffer: Option<String>,
    pub ip: Option<Vec<std::net::IpAddr>>,
}

impl Default for PcapFilter {
    fn default() -> Self {
        PcapFilter {
            src_ip: None,
            dest_ip: None,
            src_port: None,
            dest_port: None,
            timestamp: Some("1970-01-01T00:00:00Z".to_string()),
            port: None,
            buffer: Some("0".to_string()),
            ip: None,
        }
    }
}

#[derive(Parser)]
pub struct Cli {
    #[arg(help = "Config file", short = 'c', long = "config")]
    pub config_file: Option<String>,

    #[arg(
        help = "PCAP file to parse",
        short = 'f',
        long = "file",
        conflicts_with = "pcap_dir"
    )]
    pub pcap_file: Option<std::path::PathBuf>,

    #[arg(
        help = "Directory for Suricata PCAP files",
        short = 'l',
        long = "pcap_dir",
        conflicts_with = "pcap_file"
    )]
    pub pcap_dir: Option<String>,

    #[arg(
        help = "Timestamp of the flow",
        long = "ts",
        conflicts_with = "no_timestamp"
    )]
    pub timestamp: Option<String>,

    #[arg(help = "IP to filter on", long = "ip")]
    pub ip: Vec<std::net::IpAddr>,

    #[arg(help = "Source IP to filter on", long = "src_ip")]
    pub src_ip: Option<std::net::IpAddr>,

    #[arg(help = "Destination IP to filter on", long = "dest_ip")]
    pub dest_ip: Option<std::net::IpAddr>,

    #[arg(help = "Source port to filter on", long = "src_port")]
    pub src_port: Option<u16>,

    #[arg(help = "Destination port to filter on", long = "dest_port")]
    pub dest_port: Option<u16>,

    #[arg(help = "Port to filter on", long = "port")]
    pub port: Vec<u16>,

    #[arg(
        help = "Log level (e.g., debug, info, warn, error)",
        long = "log-level"
    )]
    pub log_level: Option<String>,

    #[arg(
        help = "If no timestamp is given, use this flag to search all pcap files",
        long = "no-timestamp"
    )]
    pub no_timestamp: bool,

    #[arg(help = "Run API server", long = "server")]
    pub server: bool,
}
// Function to read configuration from a file
pub fn read_config(config_path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_contents = fs::read_to_string(config_path)?; // Read the contents of the config file
    let config: Config = toml::from_str(&config_contents)?; // Parse the contents into a Config struct
    Ok(config)
}

// Function to ensure that a directory exists
pub fn ensure_dir_exists(dir: &str) -> std::io::Result<()> {
    let path = Path::new(dir);
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Directory does not exist",
        ));
        //fs::create_dir_all(path)?; // create_dir_all is used to create the
        //directory and all its parent directories if they do not exist
    }
    Ok(())
}
