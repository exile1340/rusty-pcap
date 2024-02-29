// Import necessary libraries
use std::io;
use regex::Regex;

// Define a custom error for when setting the directory for pcap files fails
#[derive(Debug)]
pub struct PcapDirError;

// Implement the Display trait for PcapDirError to control how it's printed
impl std::fmt::Display for PcapDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Failed to set directory for pcap files")
    }
}

// Implement the Error trait for PcapDirError
impl std::error::Error for PcapDirError {}

// Function to validate ports
// This function returns an error if no ports are provided
pub fn validate_ports(ports: &[u16]) -> Result<(), std::io::Error> {
    if ports.is_empty() {
        log::error!("No port filters were given");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No port filters were given",
        ));
    }
    Ok(())
}

// Function to validate the format of the flow time
// This function uses a regular expression to ensure the flow time is in the format: YYYY-MM-DDThh:mm:ss.sssZ
// If the flow time does not match this format, the function returns an error
pub fn validate_flow_time(flow_time: &str) -> Result<(), io::Error> {
    log::debug!("Validating timestamp: {}", flow_time);
    let re = Regex::new(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-](\d{2})(|:)(\d{2}))$").unwrap();
    if !re.is_match(flow_time) {
        log::error!("Timestamp provided is not in the expected format: YYYY-MM-DDThh:mm:ss.sssZ: {}", flow_time);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Timestamp provided is not in the expected format: YYYY-MM-DDThh:mm:ss.sssZ",
        ));
    }
    Ok(())
}