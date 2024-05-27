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
 * This file contains the code that handles pcap searches from the command line.
 */

// Import necessary libraries and modules
use crate::input_validation;
use crate::packet_parse;
use crate::search_pcap;
use crate::write_pcap::pcap_to_write;
use crate::Cli;
use crate::Config;
use crate::PcapFilter;
use chrono::DateTime;
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::path::PathBuf;
use std::time::Instant;

pub fn run_cli_search(
    filter: PcapFilter,
    args: Cli,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate if timestamp is valid and set to timestamp
    log::debug!("Starting CLI Search");
    let mut args = args;
    let timestamp = if let Some(ref ts) = args.timestamp {
        input_validation::validate_flow_time(ts)?;
        ts.clone()
    } else {
        args.timestamp = Some("1970-01-01T00:00:00Z".to_string());
        "1970-01-01T00:00:00Z".to_string()
    };

    log::debug!("Flow start time: {}", timestamp);
    // If timestamp is not set, check if --no-timestamp flag was used
    if timestamp == "1970-01-01T00:00:00Z" && !args.no_timestamp {
        log::error!("Timestamp not set and the --no-timestamp flag was not used");
        std::process::exit(1);
    } else if args.no_timestamp {
        log::warn!("No timestamp filter is set, this could take a long time...");
    }

    input_validation::validate_ports(&args.port)?;

    // create pcap file to write matched packet to
    let mut pcap_writer = pcap_to_write(&filter, config.output_directory.as_deref());

    // If a single pcap file was provided, only search that file
    if args.pcap_file.is_some() {
        log::info!("Searching single pcap file {:?}", args.pcap_file);
        let file_name = File::open(args.pcap_file.as_ref().unwrap().as_path())?;
        let mut pcap_reader = PcapReader::new(file_name)?;
        while let Some(Ok(packet)) = pcap_reader.next_packet() {
            if packet_parse::packet_parse(&packet, &filter) {
                pcap_writer.write_packet(&packet).unwrap();
            }
        }
    // Else search the pcap directory for all pcap files
    } else {
        let start = Instant::now();
        log::info!("Searching Pcap directory {:?}", &config.pcap_directory);
        // Set the directory for pcap files as a PathBuf
        let pcap_directory: Vec<String> = config
            .pcap_directory
            .as_ref()
            .unwrap()
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        let mut file_list: Vec<PathBuf> = Vec::new();
        for dir in pcap_directory {
            file_list.extend(
                search_pcap::directory(
                    PathBuf::from(&dir),
                    DateTime::parse_from_str(&timestamp.clone(), "0")?,
                    config.search_buffer.as_ref().unwrap_or(&"0".to_string()),
                )
                .unwrap_or_else(|_| {
                    log::error!("Failed to get file list from directory: {:?}", &dir);
                    Vec::new()
                }),
            )
        }
        log::debug!("Files to search: {:?}", file_list);
        // look at every file
        for file in file_list {
            let file_name = File::open(file.as_path())?;
            let mut pcap_reader = PcapReader::new(file_name)?;
            while let Some(Ok(packet)) = pcap_reader.next_packet() {
                if packet_parse::packet_parse(&packet, &filter) {
                    pcap_writer.write_packet(&packet).unwrap();
                }
            }
        }
        let duration = start.elapsed();
        log::info!("Pcap search took: {:?} seconds", duration.as_secs_f64());
    }

    Ok(())
}
