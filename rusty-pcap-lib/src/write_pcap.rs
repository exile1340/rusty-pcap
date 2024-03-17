// Import necessary libraries and modules
use pcap_file::pcap::PcapWriter;
use std::fs::File;
use std::env;
use std::path::Path;
use std::fs;
use crate::PcapFilter;

fn is_valid_path(path: Option<&str>) -> bool {
    if path.is_none() {
        return false;
    }
    if path.unwrap() == "" {
        return false;
    }
    let path = Path::new(path.unwrap());
    path.exists() && fs::metadata(path).is_ok()
}

fn if_full_path(path: Option<&str>) -> bool {
    match path {
        Some(s) => s.starts_with('/'),
        None => false,
    }
}

// Function to create a new pcap file writer with a name based on the given PcapFilter and directory.
pub fn pcap_to_write(args: &PcapFilter, output_dir: Option<&str>) -> PcapWriter<File> {
    // Get current directory
    let mut full_path;
    let current_dir = env::current_dir().unwrap();
    if !is_valid_path(output_dir)  {
        full_path = current_dir;
        log::error!("Output pcap directory does not exist: {:?}", output_dir);
        log::warn!("Setting pcap directory to {:?}", full_path);
    } else {
        if if_full_path(output_dir) {
            full_path = output_dir.unwrap().into();
        } else {
            full_path = current_dir.join(output_dir.unwrap());
        }
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


// Tests
#[cfg(test)]
mod tests {
    use super::*;
    mod  file_creation_test {
        use super::*;
        use std::net::Ipv4Addr;
        use std::fs;
        #[test]
        fn test_pcap_to_write_src_and_dest () {
            // Create a temporary directory for the test
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_dir_path = temp_dir.path().to_str().unwrap();

            // Create a PcapFilter instance for testing
            let filter = PcapFilter {
                ip: None,
                port: None,
                src_ip: Some(Ipv4Addr::new(127, 0, 0, 1).into()),
                src_port: Some(8080),
                dest_ip: Some(Ipv4Addr::new(192, 168, 1, 1).into()),
                dest_port: Some(80),
                timestamp: Some("2024-03-07T12:34:56Z".to_string()),
                buffer: None,
            };

            // Call the function with the test filter and temporary directory
            let pcap_writer = pcap_to_write(&filter, Some(temp_dir_path));

            // Check if the pcap file was created successfully
            print!("{:?}",pcap_writer);
            let expected_file_name = format!("{}/2024-03-07T12-34-56Z_src-ip-127.0.0.1_src-port-8080_dest-ip-192.168.1.1_dest-port-80.pcap", temp_dir_path);
            assert!(fs::metadata(&expected_file_name).is_ok());

            // Clean up: Close the pcap writer and remove the temporary directory
            drop(pcap_writer);
            temp_dir.close().unwrap();
        }

        #[test]
        fn test_pcap_to_write_ip_and_ports () {
            // Create a temporary directory for the test
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_dir_path = temp_dir.path().to_str().unwrap();

            // Create a PcapFilter instance for testing
            let filter = PcapFilter {
                ip: Some(vec![Ipv4Addr::new(127, 0, 0, 1).into(), Ipv4Addr::new(127, 0, 0, 2).into()]),
                port: Some(vec![80, 443]),
                src_ip: None,
                src_port: None,
                dest_ip: None,
                dest_port: None,
                timestamp: Some("2024-03-07T12:34:56Z".to_string()),
                buffer: None,
            };

            // Call the function with the test filter and temporary directory
            let pcap_writer = pcap_to_write(&filter, Some(temp_dir_path));

            // Check if the pcap file was created successfully
            print!("{:?}",pcap_writer);
            let expected_file_name = format!("{}/2024-03-07T12-34-56Z_127.0.0.1_127.0.0.2_80_443.pcap", temp_dir_path);
            assert!(fs::metadata(&expected_file_name).is_ok());

            // Clean up: Close the pcap writer and remove the temporary directory
            drop(pcap_writer);
            temp_dir.close().unwrap();
        }

        #[test]
        fn exits_program_if_pcap_writer_not_created() {
            // set directory to somewhere it doesn't have permissions
            let temp_dir_path = "/bin";
            let args = PcapFilter {
                timestamp: None,
                ip: Some(vec![]),
                port: None,
                src_ip: None,
                src_port: None,
                dest_ip: None,
                dest_port: None,
                buffer: None,
            };

            // Act
            let result = std::panic::catch_unwind(|| {
                pcap_to_write(&args, Some(temp_dir_path));
            });
            
            // Assert
            assert!(result.is_err());
        }

        #[test]
        fn test_pcap_to_write_invalid_directory() {
            
            let temp_dir = env::current_dir().unwrap();

            // Create a PcapFilter instance with sample data
            let filter = PcapFilter {
                ip: None,
                port: None,
                src_ip: Some(Ipv4Addr::new(127, 0, 0, 1).into()),
                src_port: Some(8080),
                dest_ip: Some(Ipv4Addr::new(192, 168, 1, 1).into()),
                dest_port: Some(80),
                timestamp: Some("2024-03-07T12:34:56Z".to_string()),
                buffer: None,
            };

            // Call the function with the test filter and an invalid directory
            let invalid_directory = "/path/that/does/not/exist";
            let result = pcap_to_write(&filter, Some(invalid_directory));
            let expected_file_name = format!("{}/2024-03-07T12-34-56Z_src-ip-127.0.0.1_src-port-8080_dest-ip-192.168.1.1_dest-port-80.pcap", temp_dir.to_str().unwrap());
            print!("{:?}", result);
            assert!(fs::metadata(&expected_file_name).is_ok());
            // Clean up: Close the pcap writer and remove the temporary directory
            drop(result);
            fs::remove_file("2024-03-07T12-34-56Z_src-ip-127.0.0.1_src-port-8080_dest-ip-192.168.1.1_dest-port-80.pcap").unwrap();
        }
    }

    mod directory_test {
        use super::*;
        #[test]
        fn returns_false_if_valid_path_not_provided() {
            // Arrange
            let path = Some("/path/does/not/exist/");

            // Act
            let result = is_valid_path(path);

            // Assert
            assert_eq!(result, false);
        }

        #[test]
        fn returns_false_if_empty_string_provided_as_path() {
            // Arrange
            let path = Some("");

            // Act
            let result = is_valid_path(path);

            // Assert
            assert_eq!(result, false);
        }

        #[test]
        fn returns_true_if_valid_path_provided() {
            // Arrange
            let path = env::current_dir().unwrap();

            // Act
            let result = is_valid_path(path.to_str());

            // Assert
            assert_eq!(result, true);
        }
    }

    mod path_tests {
        use super::*;
    
        #[test]
        fn returns_false_if_path_is_none() {
            let path = None;
            assert_eq!(if_full_path(path), false);
        }
    
        #[test]
        fn returns_false_if_path_does_not_start_with_slash() {
            let path = Some("relative/path");
            assert_eq!(if_full_path(path), false);
        }
    
        #[test]
        fn returns_true_if_path_starts_with_slash() {
            let path = Some("/absolute/path");
            assert_eq!(if_full_path(path), true);
        }
    }

    mod filter_to_name_tests {
        use super::*;
        use std::net::Ipv4Addr;
    
        #[test]
        fn test_filter_to_name_with_timestamp() {
            let filter = PcapFilter {
                timestamp: Some("2024-03-07T12:34:56Z".to_string()),
                ip: None,
                port: None,
                src_ip: None,
                src_port: None,
                dest_ip: None,
                dest_port: None,
                buffer: None,
            };
    
            let expected = "2024-03-07T12-34-56Z.pcap";
            assert_eq!(filter_to_name(&filter), expected);
        }
    
        #[test]
        fn test_filter_to_name_with_ips_and_ports() {
            let filter = PcapFilter {
                timestamp: None,
                ip: Some(vec![Ipv4Addr::new(127, 0, 0, 1).into()]),
                port: Some(vec![80]),
                src_ip: None,
                src_port: None,
                dest_ip: None,
                dest_port: None,
                buffer: None,
            };
    
            let expected = "127.0.0.1_80.pcap";
            assert_eq!(filter_to_name(&filter), expected);
        }
    
        #[test]
        fn test_filter_to_name_with_src_and_dest() {
            let filter = PcapFilter {
                timestamp: None,
                ip: None,
                port: None,
                src_ip: Some(Ipv4Addr::new(192, 168, 1, 1).into()),
                src_port: Some(8080),
                dest_ip: Some(Ipv4Addr::new(10, 0, 0, 1).into()),
                dest_port: Some(80),
                buffer: None,
            };
    
            let expected = "src-ip-192.168.1.1_src-port-8080_dest-ip-10.0.0.1_dest-port-80.pcap";
            assert_eq!(filter_to_name(&filter), expected);
        }
    
        #[test]
        fn test_filter_to_name_with_all_fields() {
            let filter = PcapFilter {
                timestamp: Some("2024-03-07T12:34:56Z".to_string()),
                ip: Some(vec![Ipv4Addr::new(127, 0, 0, 1).into(), Ipv4Addr::new(127, 0, 0, 2).into()]),
                port: Some(vec![80, 443]),
                src_ip: Some(Ipv4Addr::new(192, 168, 1, 1).into()),
                src_port: Some(8080),
                dest_ip: Some(Ipv4Addr::new(10, 0, 0, 1).into()),
                dest_port: Some(80),
                buffer: None,
            };
    
            let expected = "2024-03-07T12-34-56Z_127.0.0.1_127.0.0.2_80_443_src-ip-192.168.1.1_src-port-8080_dest-ip-10.0.0.1_dest-port-80.pcap";
            assert_eq!(filter_to_name(&filter), expected);
        }
    }
}
