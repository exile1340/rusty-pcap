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

// Import required modules
use rusty_pcap_lib::{
    api_server, cert_gen, cli::run_cli_search, ensure_dir_exists, pcap_agent, read_config, Cli,
    PcapFilter,
};
use clap::Parser;

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args = Cli::parse();

    // Read the configuration file
    let mut config = match read_config(args.config_file.as_deref().unwrap_or("config.toml")) {
        Ok(mut config) => {
            if config.pcap_agent.is_none() {
                config.pcap_agent = Some(pcap_agent::PcapAgentConfig::default());
            };
            config
        }
        Err(err) => {
            eprintln!("Failed to read config file: {}.\nPlease provide the path to the file with --config or run the application from a directory containing the config.toml file.", err);
            std::process::exit(1);
        }
    };

    // If a local config file is present overwrite the config values
    if let Ok(local_settings) = read_config("config.local.toml") {
        if let Some(local_server_settings) = local_settings.server {
            if let Some(ref mut server_config) = config.server {
                if let Some(address) = local_server_settings.address {
                    server_config.address = Some(address);
                }
                if let Some(port) = local_server_settings.port {
                    server_config.port = Some(port);
                }
                if let Some(cert) = local_server_settings.cert {
                    server_config.cert = Some(cert);
                }
                if let Some(key) = local_server_settings.key {
                    server_config.key = Some(key);
                }
                if let Some(ca_cert) = local_server_settings.ca_cert {
                    server_config.ca_cert = Some(ca_cert);
                }
                if let Some(enable_mtls) = local_server_settings.enable_mtls {
                    server_config.enable_mtls = Some(enable_mtls);
                }
                if let Some(mtls_mandatory) = local_server_settings.mtls_mandatory {
                    server_config.mtls_mandatory = Some(mtls_mandatory);
                }
                if let Some(generate_certs) = local_server_settings.generate_certs {
                    server_config.generate_certs = Some(generate_certs);
                }
                if let Some(certs_dir) = local_server_settings.certs_dir {
                    server_config.certs_dir = Some(certs_dir);
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

    // Determine if the server or pcap_agetn should be started
    let run_server = args.server || config.enable_server.unwrap();
    let run_pcap_agent = config.pcap_agent.clone().unwrap().enable;

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

    match ensure_dir_exists(&config.pcap_directory.clone().unwrap()) {
        Ok(_) => log::info!("Pcap directory exists"),
        Err(e) => {
            log::error!("Failed to find the pcap directory: {}", e);
            std::process::exit(1);
        }
    }

    log::debug!("Config: \n{}", &config);

    // Handle certificate generation if enabled
    if run_server {
        if let Some(ref mut server_config) = config.server {
            let generate_certs = server_config.generate_certs.unwrap_or(false);
            if generate_certs {
                let certs_dir = server_config
                    .certs_dir
                    .clone()
                    .unwrap_or_else(|| "certs".to_string());

                // Collect server SANs from the configured address
                let mut sans: Vec<String> =
                    vec!["localhost".to_string(), "127.0.0.1".to_string()];
                if let Some(ref addr) = server_config.address {
                    if addr != "localhost" && addr != "127.0.0.1" && !sans.contains(addr) {
                        sans.push(addr.clone());
                    }
                }

                log::info!("Certificate auto-generation is enabled");
                log::info!("  Certificates directory: {}", certs_dir);
                log::info!("  Server SANs: {:?}", sans);

                match cert_gen::ensure_certificates(&certs_dir, &sans) {
                    Ok(paths) => {
                        // Auto-configure TLS paths if not already set
                        if server_config.cert.is_none() {
                            log::info!(
                                "Auto-configuring server cert path: {}",
                                paths.server_cert
                            );
                            server_config.cert = Some(paths.server_cert);
                        }
                        if server_config.key.is_none() {
                            log::info!(
                                "Auto-configuring server key path: {}",
                                paths.server_key
                            );
                            server_config.key = Some(paths.server_key);
                        }
                        if server_config.ca_cert.is_none()
                            && server_config.enable_mtls.unwrap_or(false)
                        {
                            log::info!(
                                "Auto-configuring CA cert path for mTLS: {}",
                                paths.ca_cert
                            );
                            server_config.ca_cert = Some(paths.ca_cert.clone());
                        }

                        log::info!("Certificate generation/verification complete");
                        log::info!(
                            "  Client cert for connecting: {}",
                            paths.client_cert
                        );
                        log::info!(
                            "  Client key for connecting:  {}",
                            paths.client_key
                        );
                    }
                    Err(e) => {
                        log::error!("Failed to generate certificates: {}", e);
                        log::error!(
                            "The server will attempt to start without auto-generated certificates"
                        );
                    }
                }
            } else {
                log::debug!("Certificate auto-generation is disabled");
                log::debug!(
                    "  Set 'generate_certs = true' in [server] config to enable"
                );
            }
        }
    }

    let mut tasks = Vec::new();

    match ensure_dir_exists(&config.output_directory.clone().unwrap()) {
        Ok(_) => log::info!("Pcap output directory exists or was created successfully"),
        Err(e) => {
            log::error!("Failed to find the output directory: {}", e);
            std::process::exit(1);
        }
    }

    // If the pcap_agent is enabled, start the pcap_agent task
    if run_pcap_agent {
        log::info!("Starting Pcap Agent...");
        let mut pcap_config = config.pcap_agent.clone().unwrap();
        pcap_config.output_directory = config.output_directory.clone();
        pcap_config.pcap_directory = config.pcap_directory.clone();
        pcap_config.buffer = config.search_buffer.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = rusty_pcap_lib::pcap_agent::pcap_agent_manager(pcap_config).await {
                log::error!("Error in pcap_agent: {}", e);
            }
        });
        tasks.push(task);
    }

    // If the server is enabled, start the server task
    if run_server {
        log::info!("Starting API server...");
        let task = tokio::spawn(async move {
            if let Err(e) = api_server::rocket(config).launch().await {
                log::error!("Error in API server: {}", e);
            }
        });
        tasks.push(task);
    } else if !run_pcap_agent {
        // If neither the server nor the pcap_agent is enabled, run the CLI search
        run_cli_search(pcap_filter, args, &config)?;
    }

    // Wait for all tasks to complete
    for task in tasks {
        let _ = task.await;
    }

    Ok(())
}
