use rocket::fs::NamedFile;
use std::path::PathBuf;
use rocket::response::status::Custom;
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::Request;
use crate::write_pcap::{self, PcapFilter};
use std::time::Instant;
use crate::search_pcap;
use std::fs::File;
use pcap_file::pcap::PcapReader;
use crate::packet_parse;
use crate::Config;

struct CustomError(&'static str);

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
    let output_pcap_file = write_pcap::filter_to_name(&pcap_request);
    let mut pcap_writer = write_pcap::pcap_to_write(&pcap_request, config.output_directory.as_deref());
    // Start timer for how long the pcap search takes
    let start = Instant::now();
    log::info!("Searching Pcap directory {:?}", &config.pcap_directory);
    // Set the directory for pcap files as a PathBuf
    let pcap_directory = PathBuf::from(config.pcap_directory.as_ref().unwrap());
    let file_list = search_pcap::directory(pcap_directory, &pcap_request.timestamp.clone().unwrap_or_default(), &pcap_request.buffer.as_ref().unwrap_or(&"0".to_string())).unwrap_or_else(|_| {
        log::error!("Failed to get file list from directory: {:?}", &config.pcap_directory);
        Vec::new()
    });
    log::debug!("Files to search: {:?}", file_list);

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
async fn pcap(pcap_request: Option<PcapFilter>, config: &rocket::State<Config>) -> Result<NamedFile, Custom<String>> {
    match pcap_request {
        Some(request) => {
            get_pcap(request, config.inner()).await
        }
        None => Err(Custom(Status::BadRequest, format!("Missing parameters: {:?}", pcap_request))),
    }
}

pub fn rocket(config: crate::Config) -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .manage(config)
        .mount("/", routes![pcap])
        .mount("/", routes![index])
}