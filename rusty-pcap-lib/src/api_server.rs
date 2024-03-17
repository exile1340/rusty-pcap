use lazy_static::lazy_static;
use rocket::fs::NamedFile;
use std::path::PathBuf;
use rocket::response::status::Custom;
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::fairing::{Fairing, Info, Kind};
use crate::PcapFilter;
use std::time::Instant;
use crate::search_pcap;
use std::fs::File;
use pcap_file::pcap::PcapReader;
use crate::packet_parse;
use crate::Config;
use std::sync::Mutex;
use rocket::{routes, get, Build, Request, Rocket};
use rocket::request::{self, FromRequest};
use crate::write_pcap::{pcap_to_write, filter_to_name};

use std::sync::atomic::{AtomicU64, Ordering};

// Global variable to store the start time of the server
lazy_static! {
    static ref START_TIME: Mutex<Instant> = Mutex::new(Instant::now());
    static ref PCAP_RESPONSE_TIME_TOTAL: AtomicU64 = AtomicU64::new(0);
    static ref PCAP_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
}

// Global variable to track number of requests to the server
static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
struct CustomError(&'static str);
struct UptimeTracker;

#[rocket::async_trait]
impl Fairing for UptimeTracker {
    fn info(&self) -> Info {
        Info {
            name: "Uptime Tracker",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        *START_TIME.lock().unwrap() = Instant::now();
        Ok(rocket)
    }
}

struct RequestCounter;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestCounter {
    type Error = ();

    async fn from_request(_request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        REQUEST_COUNT.fetch_add(1, Ordering::Acquire);
        request::Outcome::Success(RequestCounter)
    }
}

impl<'r> Responder<'r, 'static> for CustomError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        response::Response::build()
            .status(Status::BadRequest)
            .sized_body(self.0.len(), std::io::Cursor::new(self.0))
            .ok()
    }
}

async fn get_pcap(pcap_request: PcapFilter, config: &Config) -> Result<NamedFile, Custom<String>> {

    // create pcap file to write matched packet to
    let output_pcap_file = filter_to_name(&pcap_request);
    let mut pcap_writer = pcap_to_write(&pcap_request, config.output_directory.as_deref());
    // Start timer for how long the pcap search takes
    let start = Instant::now();
    let pcap_directory: Vec<String> = config.pcap_directory.as_ref().unwrap().split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
    log::info!("Searching Pcap directory {:?}", &pcap_directory);
    // Set the directory for pcap files as a PathBuf
    //let pcap_directory = PathBuf::from(config.pcap_directory.as_ref().unwrap());
    let mut file_list: Vec<PathBuf> = Vec::new();
    for dir in pcap_directory {
        file_list.extend(search_pcap::directory(PathBuf::from(&dir), &pcap_request.timestamp.clone().unwrap_or_default(), &pcap_request.buffer.as_ref().unwrap_or(&"0".to_string())).unwrap_or_else(|_| {
            log::error!("Failed to get file list from directory: {:?}", &dir);
            Vec::new()
        }))
    };
    log::info!("{:?} Pcap files to search", file_list.len());
    log::debug!("Files: {:?}", file_list);

    // look at every file 
    for file in file_list {
        let path = file.as_path();
        match File::open(&path) {
            Ok(file) => {
                match PcapReader::new(file) {
                    Ok(mut pcap_reader) => {
                        while let Some(Ok(packet)) = pcap_reader.next_packet() {
                            if packet_parse::packet_parse(&packet, &pcap_request) {
                                if let Err(err) = pcap_writer.write_packet(&packet) {
                                    log::error!("Error writing packet to output pcap file: {}", err);
                                }
                            }
                        }
                    },
                    Err(_) => {
                        log::error!("Failed to create PcapReader for file: {:?}", path);
                    }
                }
            },
            Err(_) => {
                log::error!("Failed to open file: {:?}", path);
            }
        }
    }

    let duration = start.elapsed();
    log::info!("Pcap search took: {:?} seconds", duration.as_secs_f64());
    let file_path = PathBuf::from(config.output_directory.as_ref().unwrap().to_owned()+"/"+&output_pcap_file);
    log::info!("Sending {:?} back to requestor.", file_path);
    NamedFile::open(file_path)
        .await
        .map_err(|_| Custom(Status::NotFound, "File not found".to_string()))

}

#[get("/")]
fn index() -> &'static str {
    "Welcome to the Rusty PCAP agent."
}

#[get("/pcap?<pcap_request..>")]
async fn pcap(pcap_request: Option<PcapFilter>, config: &rocket::State<Config>, _counter: RequestCounter) -> Result<NamedFile, Custom<String>> {
    let start_time = Instant::now();

    let result = match pcap_request {
        Some(request) => {
            get_pcap(request, config.inner()).await
        }
        None => Err(Custom(Status::BadRequest, format!("Missing parameters: {:?}", pcap_request))),
    };

    let response_time = start_time.elapsed().as_millis() as u64;
    PCAP_RESPONSE_TIME_TOTAL.fetch_add(response_time, Ordering::Relaxed);
    PCAP_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

    result
}

#[get("/status")]
fn status() -> String {
    let start_time = START_TIME.lock().unwrap();
    let uptime_seconds = start_time.elapsed().as_secs();
    let request_count = REQUEST_COUNT.load(Ordering::Relaxed);
    let pcap_request_count = PCAP_REQUEST_COUNT.load(Ordering::Relaxed);
    let pcap_response_time_total = PCAP_RESPONSE_TIME_TOTAL.load(Ordering::Relaxed);
    let average_pcap_response_time = if pcap_request_count > 0 {
        pcap_response_time_total / pcap_request_count
    } else {
        0
    };

    let days = uptime_seconds / 86_400; // 60 * 60 * 24
    let hours = (uptime_seconds % 86_400) / 3_600; // (seconds % seconds_per_day) / seconds_per_hour
    let minutes = (uptime_seconds % 3_600) / 60; // (seconds % seconds_per_hour) / seconds_per_minute

    format!("Server uptime: {} days, {} hours, {} minutes\nTotal PCAPs served since start: {}\nAverage pcap response time: {} ms", days, hours, minutes, request_count, average_pcap_response_time)
}

pub fn rocket(config: crate::Config) -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(UptimeTracker)
        .manage(config)
        .mount("/", routes![pcap])
        .mount("/", routes![index])
        .mount("/", routes![status])
}