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

// Import necessary libraries and modules
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