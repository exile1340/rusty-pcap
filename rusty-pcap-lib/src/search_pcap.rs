// Import necessary libraries and modules
use chrono::{DateTime, Duration, FixedOffset, LocalResult, TimeZone, Utc};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

// Define the custom error for the parsing of the BufferUnit enum
#[derive(Debug)]
enum BufferParseError {
    InvalidFormat,
}

// Define the BufferUnit enum
#[derive(Debug, PartialEq)]
enum BufferUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
}

// Implement the FromStr trait for BufferUnit enum
impl FromStr for BufferUnit {
    type Err = BufferParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "s" => Ok(BufferUnit::Seconds),
            "m" => Ok(BufferUnit::Minutes),
            "h" => Ok(BufferUnit::Hours),
            "d" => Ok(BufferUnit::Days),
            _ => Err(BufferParseError::InvalidFormat),
        }
    }
}

// Function to parse the duration from a string
fn parse_duration(input: &str) -> i64 {
    let (value, unit) = if let Some(last_char) = input.chars().last() {
        match last_char {
            's' | 'm' | 'h' | 'd' => (&input[..input.len() - 1], Some(last_char.to_string())),
            _ => (input, None),
        }
    } else {
        log::error!("Search buffer is not defined properly, defaulting to 0 seconds");
        return 0;
    };

    let number = match value.parse::<i64>() {
        Ok(num) => num,
        Err(_) => {
            log::error!("Search buffer is not defined properly, defaulting to 0 seconds");
            return 0;
        }
    };

    let unit = match unit.as_deref().unwrap_or("s").parse::<BufferUnit>() {
        Ok(u) => u,
        Err(_) => {
            log::error!("Search buffer is not defined properly, defaulting to 0 seconds");
            return 0;
        }
    };

    match unit {
        BufferUnit::Seconds => number,
        BufferUnit::Minutes => number * 60,
        BufferUnit::Hours => number * 3600,
        BufferUnit::Days => number * 86400,
    }
}

// Function to return all pcap files in the directory that match the conditions
pub fn directory(path: PathBuf, time: &str, buffer: &String) -> Result<Vec<PathBuf>, io::Error> {
    let mut matching_files = Vec::new();
    let buffer_parsed = parse_duration(buffer);
    log::debug!(
        "Searching {:?} for pcap files at {} with buffer of {} seconds",
        path,
        time,
        buffer_parsed
    );

    // Read the directory
    for entry in fs::read_dir(&path)? {
        let entry = entry?;
        let path_buf = entry.path();

        // Check if the file is a pcap file
        if path_buf.is_dir() {
            let nested_output = directory(path_buf, time, buffer)?;
            matching_files.extend(nested_output);
        } else if is_pcap_file(&path_buf) {
            log::debug!("{:?} is a pcap file.", &path_buf);
            let file_name_os_str = &path_buf.file_name();
            let path_str = file_name_os_str.and_then(OsStr::to_str);
            let last_modified = extract_modified_time(&path_buf)?;

            let timestamp = extract_timestamp_from_filename(&path_str);

            // Check if timestamp from the file name is valid
            if let Some(file_time) = timestamp {
                log::debug!(
                    "Pcap file started at {:?} and ended at {}",
                    Utc.timestamp_opt(file_time, 0),
                    last_modified
                );
                match Utc.timestamp_opt(file_time, 0) {
                    LocalResult::Single(file_time) => {
                        let flow_time: DateTime<FixedOffset> = DateTime::parse_from_rfc3339(time)
                            .or_else(|_| DateTime::parse_from_str(time, "%Y-%m-%dT%H:%M:%S%.f%z"))
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("The timestamp provided is not valid {}", e),
                                )
                            })?;
                        log::debug!(
                            "Flow time: {} with buffer {} seconds",
                            flow_time,
                            buffer_parsed
                        );
                        let flow_time = flow_time.with_timezone(&Utc);
                        if (flow_time + Duration::seconds(buffer_parsed)) >= file_time
                            && (flow_time - Duration::seconds(buffer_parsed)) <= last_modified
                        {
                            log::debug!("{:?} matched timestamp filter", path_buf);
                            matching_files.push(path_buf)
                        } else if flow_time.timestamp() == 0 {
                            log::debug!("{:?} matched since --no-timestamp was used", path_buf);
                            matching_files.push(path_buf)
                        }
                    }
                    _ => {
                        log::warn!("Invalid timestamp on {:?}", path_str);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid timestamp",
                        ));
                    }
                }
            } else {
                log::warn!("Pcap file {:?} does not have a valid date format", path_buf)
            }
        } else {
            log::debug!("{:?} is not a pcap file", path_buf)
        }
    }
    log::debug!(
        "{} pcap files matched flow time filter in {:?}",
        matching_files.len(),
        path
    );
    Ok(matching_files)
}

// Function to extract a timestamp from a filename
fn extract_timestamp_from_filename(filename: &Option<&str>) -> Option<i64> {
    filename.and_then(|f| {
        let parts: Vec<&str> = f.split('.').collect();
        // Check for the format 'snort.log.<timestamp>.pcap'
        if parts.len() == 4
            && parts[0].starts_with("snort")
            && parts[1].starts_with("log")
            && parts[3] == "pcap"
        {
            return parts[2].parse::<i64>().ok();
        }
        // Check for the format '<timestamp>-<any_other_part>.pcap'
        let parts: Vec<&str> = f.split('-').collect();
        if parts.len() >= 2 && parts.last().map_or(false, |ext| ext.ends_with(".pcap")) {
            return parts.first().and_then(|p| p.parse::<i64>().ok());
        }
        None
    })
}

// Function to retrieve the time a file was last modified
fn extract_modified_time(file: &PathBuf) -> io::Result<DateTime<Utc>> {
    let metadata = fs::metadata(file)?;
    let modified_time = metadata.modified()?;
    let datetime = DateTime::<Utc>::from(modified_time);
    Ok(datetime)
}

// Function to check if a file is a pcap file
fn is_pcap_file(path: &Path) -> bool {
    match path.extension() {
        Some(ext) => {
            let ext_str = ext.to_str().unwrap_or("").to_lowercase();
            ext_str == "pcap" || ext_str == "pcapng"
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s"), 10);
        assert_eq!(parse_duration("5m"), 300);
        assert_eq!(parse_duration("2h"), 7200);
        assert_eq!(parse_duration("1d"), 86400);
        assert_eq!(parse_duration("invalid"), 0);
    }

    #[test]
    fn test_buffer_unit_from_str() {
        assert_eq!(BufferUnit::from_str("s").unwrap(), BufferUnit::Seconds);
        assert_eq!(BufferUnit::from_str("m").unwrap(), BufferUnit::Minutes);
        assert_eq!(BufferUnit::from_str("h").unwrap(), BufferUnit::Hours);
        assert_eq!(BufferUnit::from_str("d").unwrap(), BufferUnit::Days);
        assert!(BufferUnit::from_str("invalid").is_err());
    }

    #[test]
    fn test_extract_timestamp_from_filename() {
        assert_eq!(
            extract_timestamp_from_filename(&Some("snort.log.1609459200.pcap")),
            Some(1609459200)
        ); // 2021-01-01T00:00:00Z
        assert_eq!(
            extract_timestamp_from_filename(&Some("1609459200-something.pcap")),
            Some(1609459200)
        ); // 2021-01-01T00:00:00Z
        assert_eq!(extract_timestamp_from_filename(&Some("invalid.pcap")), None);
    }

    #[test]
    fn test_is_pcap_file() {
        assert!(is_pcap_file(&PathBuf::from("file.pcap")));
        assert!(is_pcap_file(&PathBuf::from("file.pcapng")));
        assert!(!is_pcap_file(&PathBuf::from("file.txt")));
    }

    #[test]
    fn test_directory_function() {
        // Create a temporary directory with a sample pcap file
        let temp_dir = TempDir::new().unwrap();
        let pcap_path = temp_dir.path().join("snort.log.1609459200.pcap"); // 2021-01-01T00:00:00Z
        fs::write(&pcap_path, b"").unwrap();

        // Test the directory function with a matching timestamp and buffer
        let matching_files = directory(
            temp_dir.path().to_path_buf(),
            "2021-01-01T00:00:00+00:00",
            &"1d".to_string(),
        )
        .unwrap();
        assert!(matching_files.contains(&pcap_path));

        // Test with a non-matching timestamp
        let non_matching_files = directory(
            temp_dir.path().to_path_buf(),
            "2020-01-02T00:00:00+00:00",
            &"1s".to_string(),
        )
        .unwrap();
        assert!(!non_matching_files.contains(&pcap_path));
    }
}
