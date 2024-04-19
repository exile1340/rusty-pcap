use chrono::NaiveDateTime;
use chrono::{DateTime, Duration, FixedOffset, LocalResult, TimeZone, Utc};
use regex::Regex;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::io::Read;
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

pub fn parse_time_field(time: &str) -> Result<DateTime<FixedOffset>, io::Error> {
    log::debug!("Parsing time field: {}", time);
    let patterns = [
        "%+",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%:z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
    ];

    let mut last_err = None;

    for pattern in patterns {
        log::debug!("Trying pattern: {}", pattern);
        if let Ok(dt) = DateTime::parse_from_str(time, pattern) {
            log::debug!("Parsed time field: {}", dt);
            return Ok(dt);
        } else if let Ok(naive) = NaiveDateTime::parse_from_str(time, pattern) {
            log::debug!("Parsed time field: {}", naive);
            // Assume UTC if no timezone provided
            return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
                .with_timezone(&FixedOffset::east_opt(0).unwrap()));
        } else {
            last_err = Some(format!("Failed to parse using pattern {}", pattern));
        }
    }

    log::error!("The timestamp {} is not valid. {:?}", time, last_err);
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("The timestamp {} is not valid.", time),
    ))
}

// Function to parse the duration from a string
pub fn parse_duration(input: &str) -> i64 {
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
pub fn directory(
    path: PathBuf,
    time: DateTime<FixedOffset>,
    buffer: &String,
) -> Result<Vec<PathBuf>, io::Error> {
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
            println!("is a pcap file {:?}", &path_buf);
            let file_name_os_str = &path_buf.file_name();
            let path_str = file_name_os_str.and_then(OsStr::to_str).unwrap();
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
                        let flow_time: DateTime<FixedOffset> = time;

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
                            log::debug!("{:?} matched since no timestamp was provided", path_buf);
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

fn extract_timestamp_from_filename(filename: &str) -> Option<i64> {
    let re_result = Regex::new(r"(\d{10})");
    if let Ok(re) = re_result {
        if let Some(caps) = re.captures(filename) {
            if let Some(matched) = caps.get(1) {
                let timestamp = matched.as_str().parse::<i64>();
                let timestamp = match timestamp {
                    Ok(t) => t,
                    Err(_) => {
                        log::error!("Invalid timestamp found in the filename {}", filename);
                        return None;
                    }
                };
                return Some(timestamp);
            }
        }
        log::error!("No valid timestamp found in the filename {}", filename);
        None
    } else {
        log::error!("Error creating regex for timestamp extraction");
        None
    }
}

// Function to retrieve the time a file was last modified
fn extract_modified_time(file: &PathBuf) -> io::Result<DateTime<Utc>> {
    let metadata = fs::metadata(file)?;
    let modified_time = metadata.modified()?;
    let datetime = DateTime::<Utc>::from(modified_time);
    Ok(datetime)
}

fn is_pcap_file(file_path: &Path) -> bool {
    let mut file = match std::fs::File::open(file_path) {
        Ok(file) => file,
        Err(_) => return false, // If the file cannot be opened, assume it's not a PCAP
    };

    let mut buffer = [0u8; 4]; // Buffer to hold the first four bytes
    if file.read_exact(&mut buffer).is_err() {
        return false; // If reading fails, assume it's not a PCAP
    }
    println!("{:?}", buffer);

    // Convert the bytes to a u32 using native endian
    let magic_number = u32::from_le_bytes(buffer);

    // Check if the magic number matches either of the common PCAP headers
    magic_number == 0xa1b2c3d4 || magic_number == 0xd4c3b2a1
}

#[cfg(test)]
mod tests {
    use super::*;
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
            extract_timestamp_from_filename("snort.log.1609459200.pcap"),
            Some(1609459200)
        ); // 2021-01-01T00:00:00Z
        assert_eq!(
            extract_timestamp_from_filename("1609459200-something.pcap"),
            Some(1609459200)
        ); // 2021-01-01T00:00:00Z
        assert_eq!(extract_timestamp_from_filename("invalid.pcap"), None);
    }

    #[test]
    fn test_directory_function() {
        // Create a temporary directory with a sample pcap file
        let temp_dir = TempDir::new().unwrap();
        let pcap_path = temp_dir.path().join("snort.log.1609459200.pcap"); // 2021-01-01T00:00:00Z
        fs::write(&pcap_path, b"\xA1\xB2\xC3\xD4").unwrap();

        // Test the directory function with a matching timestamp and buffer
        println!("{:?}", pcap_path);
        println!("{:?}", temp_dir.path());
        println!(
            "{:?}",
            parse_time_field("2021-01-01T00:00:00+00:00").unwrap()
        );
        let matching_files = directory(
            temp_dir.path().to_path_buf(),
            parse_time_field("2021-01-01T00:00:00+00:00").unwrap(),
            &"1d".to_string(),
        )
        .unwrap();
        println!("{:?}", matching_files);
        assert!(matching_files.contains(&pcap_path));

        // Test with a non-matching timestamp
        let non_matching_files = directory(
            temp_dir.path().to_path_buf(),
            parse_time_field("2020-01-02T00:00:00+00:00").unwrap(),
            &"1s".to_string(),
        )
        .unwrap();
        println!("{:?}", non_matching_files);
        assert!(!non_matching_files.contains(&pcap_path));
    }
}
