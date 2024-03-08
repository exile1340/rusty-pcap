use structopt::StructOpt;
use std::path::PathBuf;
use crate::input_validation;
use crate::write_pcap;
use crate::write_pcap::PcapFilter;
use crate::Config;
use std::fs::File;
use std::time::Instant;
use pcap_file::pcap::PcapReader;
use crate::packet_parse;
use crate::search_pcap;

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

pub fn run_cli_search(filter: PcapFilter, args: Cli,  config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // Validate if timestamp is valid and set to timestamp
    log::debug!("Starting CLI Search");
    let mut args= args;
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
    let mut pcap_writer = write_pcap::pcap_to_write(&filter, config.output_directory.as_deref());

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
        let pcap_directory: Vec<String> = config.pcap_directory.as_ref().unwrap().split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
        let mut file_list: Vec<PathBuf> = Vec::new();
        for dir in pcap_directory {
            file_list.extend(search_pcap::directory(PathBuf::from(&dir), &timestamp.clone(), &config.search_buffer.as_ref().unwrap_or(&"0".to_string())).unwrap_or_else(|_| {
                log::error!("Failed to get file list from directory: {:?}", &dir);
                Vec::new()
            }))
        };
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