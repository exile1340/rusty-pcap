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
 * This file contains the code that handles input validation for requests
 * received by rusty-pcap. 
 */

// Import necessary libraries and modules
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ports_empty() {
        let ports = vec![];
        let result = validate_ports(&ports);
        assert!(result.is_err(), "Expected an error for empty ports");
    }

    #[test]
    fn test_validate_ports_non_empty() {
        let ports = vec![80, 443];
        let result = validate_ports(&ports);
        assert!(result.is_ok(), "Expected no error for non-empty ports");
    }

    #[test]
    fn test_validate_flow_time_valid() {
        let flow_time = "2023-03-07T12:34:56.789Z";
        let result = validate_flow_time(flow_time);
        assert!(result.is_ok(), "Expected no error for valid flow time");
    }

    #[test]
    fn test_validate_flow_time_invalid() {
        let flow_time = "2023-03-07 12:34:56";
        let result = validate_flow_time(flow_time);
        assert!(result.is_err(), "Expected an error for invalid flow time");
    }
}