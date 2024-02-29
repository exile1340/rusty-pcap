// Import necessary libraries and modules
use pcap_file::pcap::PcapWriter;
use rocket::form::FromForm;
use std::fs::File;
use std::env;
use serde::{Deserialize, Serialize};

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

// Function to create a new pcap file writer with a name based on the given PcapFilter and directory.
pub fn pcap_to_write(args: &PcapFilter, output_dir: Option<&str>) -> PcapWriter<File> {
    // Get current directory
    let current_dir = env::current_dir().unwrap();
    // Set the filtered_pcap_file to the given directory or "output" if no directory was given
    let filtered_pcap_file = match &output_dir{
        Some(dir) => dir,
        None => "output"
    };

    // Join the directory and file paths
    let mut full_path = current_dir.join(filtered_pcap_file);
    log::info!("Output pcap directory: {:?}", full_path);
    
    // Check if the directory exists, and exit the program if it does not
    if !full_path.exists() {
        log::error!("Output pcap directory does not exist: {:?}", full_path);
        std::process::exit(1);
    }
    
    // Join the directory and file name
    full_path = full_path.join(filter_to_name(&args));
    log::info!("Pcap file to write {:?}", full_path);

    // Create the new pcap file
    let temp_file = File::create(full_path).unwrap();
    let pcap_writer = PcapWriter::new(temp_file);
    // If the pcap writer was successfully created, return it. Otherwise, log an error and exit the program.
    match pcap_writer {
        Ok(pcap_writer) => return pcap_writer,
        _pcap_error => {
            log::error!("Something went wrong getting pcap file to write");
            std::process::exit(1);
        }
    }
}

/// Function to generate a file name based on the provided PcapFilter information
pub fn filter_to_name(args: &PcapFilter) -> String {
    let mut file_name = String::new();

    // Add timestamp if not default
    // This checks if the timestamp exists and if it's not the default value
    if let Some(timestamp) = &args.timestamp {
        if timestamp != "1970-01-01T00:00:00Z" {
            file_name.push_str(timestamp);
            file_name.push('_');
        }
    }

    // Add IP addresses to the file name
    if let Some(ips) = &args.ip {
        for ip in ips {
            file_name.push_str(&ip.to_string());
            file_name.push('_');
        }
    }

    // Add ports to the file name
    if let Some(ports) = &args.port {
        for port in ports {
            file_name.push_str(&port.to_string());
            file_name.push('_');
        }
    }

    // Add source IPs to the file name
    for ip in &args.src_ip {
        file_name.push_str("src-ip-");
        file_name.push_str(&ip.to_string());
        file_name.push('_');
    }

    // Add source ports to the file name
    for port in &args.src_port {
        file_name.push_str("src-port-");
        file_name.push_str(&port.to_string());
        file_name.push('_');
    }

    // Add destination IPs to the file name
    for ip in &args.dest_ip {
        file_name.push_str("dest-ip-");
        file_name.push_str(&ip.to_string());
        file_name.push('_');
    }

    // Add destination ports to the file name
    for port in &args.dest_port {
        file_name.push_str("dest-port-");
        file_name.push_str(&port.to_string());
        file_name.push('_');
    }

    // Clean up the file name by removing trailing underscores and replacing colons with dashes
    file_name = file_name.trim_end_matches('_').to_string();
    file_name = file_name.replace(":", "-");

    // Append the .pcap extension to the file name
    file_name.push_str(".pcap");

    // Return the cleaned up file name
    file_name
}