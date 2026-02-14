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
 * This file contains the implementation of the Pcap Agent, this is a drop in replacement
 * for the pcap_agent.tcl script from Sguil https://github.com/bammv/sguil.
 * The agent connects to the Sguil server and listens for commands, it can also send data back to the server.
 * The agent can parse directories with pcap files in the sguil format or suricata format.
 */

use crate::api_server;
use crate::PcapFilter;
use chrono::FixedOffset;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use hostname;
use log::{debug, error, info, warn};
use native_tls::TlsConnector as NativeTlsConnector;
use regex::Regex;
use rocket::fs::NamedFile;
use serde::Deserialize;
use serde::Serialize;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use std::time::SystemTime;
use sysinfo::Disks;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::oneshot;
use tokio_native_tls::{TlsConnector, TlsStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

static SGUIL_CMD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(\{[^}]*\}|\S+)"#).unwrap());

// Struct to represent the configuration for the pcap agent
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PcapAgentConfig {
    pub sguil_version: String,
    pub server: String,
    pub port: String,
    pub ping_interval: u64,
    pub agent_type: String,
    pub sensor_name: String,
    pub sensor_net: String,
    pub enable: bool,
    pub pcap_directory: Option<String>,
    pub output_directory: Option<String>,
    pub disk_space_checkin: u16,
    pub file_checkin: u16,
    pub buffer: Option<String>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub skip_tls_verify: Option<bool>,
}

// Implement the default trait for PcapAgentConfig
impl Default for PcapAgentConfig {
    fn default() -> Self {
        Self {
            sguil_version: String::from("SGUIL-1.0.0"),
            server: String::from("127.0.0.1"),
            port: String::from("7736"),
            ping_interval: 30,
            agent_type: String::from("pcap"),
            sensor_name: hostname::get()
                .unwrap_or_default()
                .into_string()
                .unwrap_or_else(|_| String::from("unknown")),
            sensor_net: String::from("Int_Net"),
            enable: false,
            pcap_directory: Some(String::from("")),
            output_directory: Some(String::from("")),
            disk_space_checkin: 300,
            file_checkin: 300,
            buffer: Some(String::from("300s")),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            skip_tls_verify: Some(false),
        }
    }
}

// Enum to represent the commands received from the sguil server
#[derive(Debug)]
enum SguilCommand {
    Ping,
    Pong,
    RawDataRequest,
    AgentInfo,
}

// Function to convert a string to a SguilCommand
impl FromStr for SguilCommand {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PING" => Ok(SguilCommand::Ping),
            "PONG" => Ok(SguilCommand::Pong),
            "RawDataRequest" => Ok(SguilCommand::RawDataRequest),
            "AgentInfo" => Ok(SguilCommand::AgentInfo),
            _ => Err(()),
        }
    }
}

pub async fn pcap_agent_manager(config: PcapAgentConfig) -> io::Result<()> {
    // Token to stop the pcap agent permanently
    let should_stop = CancellationToken::new();

    // Token to track if the sguild server has crashed
    let sguild_crashed = Arc::new(AtomicBool::new(true));

    // if we haven't given the command to stop, we will keep running the pcap_agent
    // if a network error occurs, stop all the threads currently running
    // start a new pcap agent process

    // which should_stop is not cancelled, keep restarting the pcap agent
    while !should_stop.is_cancelled() {
        // check if sguild has crashed
        if sguild_crashed.load(Ordering::Relaxed) {
            info!("Restarting the pcap agent...");
            // start a new pcap agent process
            // wait for all previous threads to stop
            tokio::time::sleep(Duration::from_secs(1)).await;
            let cloned_config = config.clone();
            let cloned_should_stop = should_stop.clone();
            let cloned_sguild_crashed = sguild_crashed.clone();
            sguild_crashed.store(false, Ordering::Relaxed);
            tokio::spawn(async move {
                pcap_agent(cloned_config, cloned_should_stop, cloned_sguild_crashed).await
            });
        }
        //}

        // wait for 5 seconds before checking if sguild has crashed
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    info!("Pcap agent manager stopped...");

    Ok(())
}

// Function to start the pcap agent
pub async fn pcap_agent(
    config: PcapAgentConfig,
    should_stop: CancellationToken,
    sguild_crashed: Arc<AtomicBool>,
) -> io::Result<()> {
    info!("Starting pcap agent process...");
    let ping_interval = config.ping_interval;
    let task_tracker = TaskTracker::new();

    // connect to the sguil server
    info!("Connecting to sguil server...");
    let stream = sguil_connect(config.clone()).await?;

    // Legacy code to improve
    let mut reader = tokio::io::BufReader::new(stream);
    let response = read_line(&mut reader).await?;
    debug!("Received response: {}", response.trim());
    let stream = reader.into_inner();

    let (stream_reader, stream_writer) = tokio::io::split(stream);

    // Create channels for communication between tasks.
    let (reader_tx, command_rx) = mpsc::channel::<String>(100);
    let (command_tx, writer_rx) = mpsc::channel::<String>(100);

    // Send the first response received from the server to the reader channel.
    let _ = reader_tx.send(response).await;

    // Spawn the reader, writer, command processing, and ping tasks.
    task_tracker.spawn(
        spawn_reader_task(
            should_stop.clone(),
            sguild_crashed.clone(),
            stream_reader,
            reader_tx,
        )
        .await,
    );
    task_tracker.spawn(
        ping_task(
            should_stop.clone(),
            sguild_crashed.clone(),
            command_tx.clone(),
            ping_interval,
        )
        .await,
    );
    task_tracker.spawn(
        writer_task(
            should_stop.clone(),
            sguild_crashed.clone(),
            stream_writer,
            writer_rx,
        )
        .await,
    );
    task_tracker.spawn(
        command_task(
            should_stop.clone(),
            sguild_crashed.clone(),
            command_rx,
            command_tx.clone(),
            config.clone(),
        )
        .await,
    );
    task_tracker.spawn(
        disk_report(
            should_stop.clone(),
            sguild_crashed.clone(),
            command_tx.clone(),
            config.pcap_directory.clone().unwrap(),
            config.disk_space_checkin,
        )
        .await,
    );
    task_tracker.spawn(
        last_pcap_time(
            should_stop.clone(),
            sguild_crashed.clone(),
            command_tx.clone(),
            config.pcap_directory.unwrap(),
            config.file_checkin,
        )
        .await,
    );

    // Handle sguild crashing
    let (stop_sender, stop_receiver) = oneshot::channel();
    let stop_flag_clone = Arc::clone(&sguild_crashed);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await; // Check every 100ms
            if stop_flag_clone.load(Ordering::Relaxed) {
                let _ = stop_sender.send(());
                break;
            }
        }
    });

    // Handle SIGINT and SIGTERM signals.
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let mut term_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // Wait for the ctrl-c signal or termination signal.
    tokio::select! {
        _ = ctrl_c => {
            warn!("SIGINT received, shutting down");
            should_stop.cancel();
            task_tracker.close();
            task_tracker.wait().await;
        }
        _ = term_signal.recv() => {
            warn!("Received termination signal...");
            should_stop.cancel();
        }
        _ = stop_receiver => {
            warn!("Sguild crash, shutting down pcap agent...");
        }
    }

    Ok(())
}

// Function to send preamble to the sguil server
async fn preamble(tcp_stream: TcpStream, sguil_version: &str) -> io::Result<TcpStream> {
    debug!("Sending preamble...");
    let mut reader = tokio::io::BufReader::new(tcp_stream);
    let buffer = read_line(&mut reader).await?;
    let received = buffer.trim().split(' ').collect::<Vec<&str>>();
    debug!("Received: {:?}", received);
    let received_version = received[0]; // assuming the received message is the version

    if received_version != sguil_version {
        error!(
            "Mismatched versions.\nSERVER: ({})\nAGENT: ({})",
            received_version, sguil_version
        );
        tokio::time::sleep(Duration::from_millis(15000)).await;
    }

    let data = format!("VersionInfo {{{} OPENSSL ENABLED}}\n", sguil_version);
    match reader.write_all(data.as_bytes()).await {
        Ok(_) => {
            debug!("Successfully wrote to the stream");
            Ok(reader.into_inner())
        }
        Err(e) => {
            error!("Unable to send version string: {}", e);
            Err(e)
        }
    }
}

// Function to register the agent with the sguil server
async fn register_agent(
    mut stream: TlsStream<TcpStream>,
    sensor_type: &str,
    sensor_name: &str,
    sensor_net: &str,
) -> io::Result<TlsStream<TcpStream>> {
    debug!(
        "Sending: RegisterAgent {} {} {}",
        sensor_type, sensor_name, sensor_net
    );
    let data = format!(
        "RegisterAgent {} {} {}\n",
        sensor_type, sensor_name, sensor_net
    );
    match stream.write_all(data.as_bytes()).await {
        Ok(_) => (),
        Err(e) => {
            error!("Unable to send registration string: {}", e);
        }
    }

    Ok(stream)
}

// Function to set up the TLS stream
async fn set_up_tls(
    tcp_stream: TcpStream,
    config: &PcapAgentConfig,
) -> io::Result<TlsStream<TcpStream>> {
    let server_host: String = format!("{}:{}", config.server, config.port);
    let mut builder = NativeTlsConnector::builder();

    // Only skip TLS verification if explicitly configured
    if config.skip_tls_verify.unwrap_or(false) {
        warn!("TLS certificate verification is disabled - this is insecure!");
        builder.danger_accept_invalid_certs(true);
    }

    // Load CA certificate if provided
    if let Some(ca_cert_path) = &config.ca_cert {
        let ca_cert_pem = std::fs::read(ca_cert_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to read CA certificate at {}: {}", ca_cert_path, e),
            )
        })?;
        let ca_cert = native_tls::Certificate::from_pem(&ca_cert_pem).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse CA certificate: {}", e),
            )
        })?;
        builder.add_root_certificate(ca_cert);
    }

    // Load client certificate and key if provided (for future mTLS support)
    if let (Some(cert_path), Some(key_path)) = (&config.client_cert, &config.client_key) {
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to read client certificate at {}: {}", cert_path, e),
            )
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to read client key at {}: {}", key_path, e),
            )
        })?;
        let identity = native_tls::Identity::from_pkcs8(&cert_pem, &key_pem).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to create TLS identity from client cert/key: {}", e),
            )
        })?;
        builder.identity(identity);
    }

    let connector = builder.build().map_err(|e| {
        io::Error::other(format!("Failed to build TLS connector: {}", e))
    })?;
    let connector = TlsConnector::from(connector);

    match connector.connect(&server_host, tcp_stream).await {
        Ok(stream) => {
            debug!("TLS connection established...");
            Ok(stream)
        }
        Err(e) => {
            error!("Failed TLS connection: {}", e);
            Err(io::Error::other(format!("Failed TLS connection: {}", e)))
        }
    }
}

// Function to spawn the reader task
async fn spawn_reader_task(
    should_stop: CancellationToken,
    sguild_crashed: Arc<AtomicBool>,
    stream_reader: tokio::io::ReadHalf<TlsStream<TcpStream>>,
    reader_tx: Sender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stream_reader);
        while !sguild_crashed.load(Ordering::SeqCst) {
            let mut buffer = String::new();
            tokio::select! {
            result = reader.read_line(&mut buffer) => {
                    match result {
                        Ok(_) => {
                            let _ = reader_tx.send(buffer).await;
                        }
                        Err(e) => {
                            error!("Failed to read from stream: {}", e);
                            sguild_crashed.store(true, Ordering::SeqCst);
                            break
                        }
                    }
                }
                _ = should_stop.cancelled() => {
                    debug!("Stopping reader task");
                    break;
                }
            }
        }
    })
}

// Function to send ping to the sguil server
async fn ping_task(
    should_stop: CancellationToken,
    sguild_crashed: Arc<AtomicBool>,
    command_tx: Sender<String>,
    ping_interval: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !sguild_crashed.load(Ordering::SeqCst) {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(ping_interval)) => {
                    let data = "PING\n";
                    if let Err(e) = command_tx.send(data.to_string()).await {
                        error!("Failed to send ping: {}", e);
                        sguild_crashed.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                _ = should_stop.cancelled() => {
                    debug!("Stopping ping task");
                    break;
                }
            }
        }
    })
}

// Function to get the most recent pcap file
fn most_recent_file(path: &str) -> io::Result<String> {
    let mut most_recent_time = SystemTime::UNIX_EPOCH;
    let now = Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap());
    let most_recent =
        crate::search_pcap::directory(PathBuf::from_str(path).unwrap(), now, &"10".to_string());
    for entry in most_recent.unwrap() {
        let metadata = entry.metadata()?;
        let modified = metadata.modified()?;

        if modified > most_recent_time {
            most_recent_time = modified;
        }
    }
    let datetime: DateTime<Local> = most_recent_time.into();
    let formatted_time = datetime.format("%Y-%m-%d %T").to_string();
    Ok(formatted_time)
}

// Function to get the most recent pcap file on a regular interval
async fn last_pcap_time(
    should_stop: CancellationToken,
    sguild_crashed: Arc<AtomicBool>,
    command_tx: Sender<String>,
    pcap_directory: String,
    last_pcap_interval: u16,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !sguild_crashed.load(Ordering::SeqCst) {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(last_pcap_interval.into())) => {
                    match most_recent_file(pcap_directory.as_str()) {
                        Ok(time) => {
                            let data = format!("LastPcapTime {{{}}}\n", time);
                            if let Err(e) = command_tx.send(data.to_string()).await {
                                error!("Failed to send last pcap time: {}", e);
                                sguild_crashed.store(true, Ordering::SeqCst);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to get most recent pcap file: {}", e);
                        }
                    }
                }
                _ = should_stop.cancelled() => {
                    debug!("Stopping last pcap time task");
                    break;
                }
            }
        }
    })
}

// Function to get disk space usage on a regualar interval
async fn disk_report(
    should_stop: CancellationToken,
    sguild_crashed: Arc<AtomicBool>,
    command_tx: Sender<String>,
    pcap_directory: String,
    disk_interval: u16,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !sguild_crashed.load(Ordering::SeqCst) {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(disk_interval.into())) => {
                    let data = format!("DiskReport {}", disk_space(pcap_directory.clone()));
                    if let Err(e) = command_tx.send(data.to_string()).await {
                        error!("Failed to send disk report: {}", e);
                        sguild_crashed.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                _ = should_stop.cancelled() => {
                    debug!("Stopping disk report task");
                    break;
                }
            }
        }
    })
}

// Function to send data to the sguil server
async fn writer_task(
    should_stop: CancellationToken,
    sguild_crashed: Arc<AtomicBool>,
    mut stream_writer: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    mut writer_rx: mpsc::Receiver<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !sguild_crashed.load(Ordering::SeqCst) {
            tokio::select! {
                Some(message) = writer_rx.recv() => {
                    info!("Sending: {}", message.trim());
                    if let Err(e) = stream_writer.write(message.as_bytes()).await {
                        error!("Failed to write to stream: {}", e);
                        sguild_crashed.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                _ = should_stop.cancelled() => {
                    debug!("Stopping writer task");
                    break;
                }
            }
        }
    })
}

// Function to process commands from the command reader channel
// and send processed command to the command transmitter channel
async fn command_task(
    should_stop: CancellationToken,
    sguild_crashed: Arc<AtomicBool>,
    mut command_rx: mpsc::Receiver<String>,
    command_tx: mpsc::Sender<String>,
    config: PcapAgentConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !sguild_crashed.load(Ordering::SeqCst) {
            tokio::select! {
                Some(command) = command_rx.recv() => {
                    if command.trim().is_empty() {
                        continue;
                    }
                    info!("Received: {}", command.trim());
                    let request: Vec<&str> = SGUIL_CMD_RE.find_iter(command.trim())
                           .map(|mat| mat.as_str())
                           .collect();
                    if request.is_empty() {
                        warn!("Received empty command after parsing");
                        continue;
                    }
                    let command = match request[0].parse::<SguilCommand>() {
                        Ok(cmd) => cmd,
                        Err(_) => {
                            warn!("Unknown sguil command: {}", request[0]);
                            continue;
                        }
                    };
                    let response = process_command(command, config.clone(), request, command_tx.clone()).await;
                    if let Some(resp) = response {
                        let _ = command_tx.send(resp).await;
                    }
                }
                _ = should_stop.cancelled() => {
                    debug!("Stopping command task");
                    break;
                }
            }
        }
    })
}

// Function to read a line from the stream
async fn read_line(reader: &mut (impl AsyncBufReadExt + Unpin)) -> std::io::Result<String> {
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    Ok(buffer)
}

// Function to process commands from sguil
async fn process_command(
    command: SguilCommand,
    config: PcapAgentConfig,
    request: std::vec::Vec<&str>,
    command_tx: mpsc::Sender<String>,
) -> Option<String> {
    debug!("Processing command: {:?}", command);
    match command {
        SguilCommand::Ping => Some("PONG\n".to_string()),
        SguilCommand::Pong => None,
        SguilCommand::RawDataRequest => {
            debug!("Received RawDataRequest");
            let request: Vec<String> = request.into_iter().map(|s| s.to_string()).collect();
            let config = config.clone();
            tokio::spawn(async move { xscript_request(request, config, command_tx).await });
            None
        }
        SguilCommand::AgentInfo => {
            tokio::spawn(async move {
                agent_info(command_tx.clone(), config.clone()).await;
            });
            None
        }
    }
}

// Function to process XscriptRequest
async fn xscript_request(
    request: std::vec::Vec<String>,
    config: PcapAgentConfig,
    command_tx: mpsc::Sender<String>,
) -> io::Result<()> {
    //socketID TRANS_ID sensor timestamp srcIP dstIP srcPort dstPort proto rawDataFileName type
    //Sending pillarofautumn: RawDataRequest 11 pillarofautumn 2024-04-25 20:58:47 142.250.191.195 10.1.3.124 34696 6 10.1.3.124:34696_142.250.191.195:2561-6.raw xscript
    debug!("Processing XscriptRequest");
    let trans_id = request[1].as_str();
    let _sensor = request[2].as_str();

    let timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDateTime::parse_from_str(request[3].as_str(), "{%Y-%m-%d %H:%M:%S}")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse timestamp"))?,
        Utc,
    )
    .to_rfc3339();

    let src_ip = request[4].as_str();
    let dst_ip = request[5].as_str();
    let src_port = request[6].as_str();
    let dst_port = request[7].as_str();
    let _proto = request[8].as_str();
    let raw_data_file = request[9].as_str();
    let _type = request[10].as_str();

    info!("Request from Sguil: {:?}", request);
    // Create config for get_pcap
    // Need to improve config handling
    let search_config: crate::Config = crate::Config {
        pcap_directory: Some(config.pcap_directory.clone().unwrap()),
        output_directory: Some(config.output_directory.clone().unwrap()),
        log_level: Some("info".to_string()),
        enable_server: Some(false),
        search_buffer: Some(config.buffer.clone().unwrap()),
        server: None,
        enable_cors: false,
        pcap_agent: None,
    };

    // Create pcap filter
    let pcap_filter: crate::PcapFilter = PcapFilter {
        ip: Some(vec![src_ip.parse().unwrap(), dst_ip.parse().unwrap()]),
        port: Some(vec![src_port.parse().unwrap(), dst_port.parse().unwrap()]),
        src_ip: None,
        src_port: None,
        dest_ip: None,
        dest_port: None,
        timestamp: Some(timestamp.to_string()),
        buffer: search_config.search_buffer.clone(),
    };

    debug!("Calling get_pcap");
    debug!("PcapFilter: {:?}", pcap_filter);
    debug!("Config: {:?}", search_config);
    let _ = command_tx
        .send(
            format!(
                "XscriptDebugMsg {} {{Searching for pcap file.....}}\n",
                trans_id
            )
            .to_string(),
        )
        .await;
    let pcap = api_server::get_pcap(pcap_filter, &search_config)
        .await
        .unwrap();

    debug!("Sending pcap back to sguil: {:?}", pcap);
    match data_agent(config, pcap, raw_data_file, trans_id).await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to send pcap to sguil: {}", e);
        }
    }
    let _ = command_tx
        .send(format!("XscriptResponse {} {{Done}}\n", trans_id).to_string())
        .await;

    Ok(())
}

// Function to set up data agent and send pcap file to sguil
async fn data_agent(
    mut config: PcapAgentConfig,
    pcap_file: NamedFile,
    raw_data_file: &str,
    trans_id: &str,
) -> io::Result<()> {
    config.agent_type = "data".to_string();
    let mut data_stream = sguil_connect(config).await?;
    let should_stop = CancellationToken::new();
    let task_tracker = TaskTracker::new();

    //RawDataFile $fileName $TRANS_ID $fileSize
    let metadata = std::fs::metadata(pcap_file.path())?;
    let file_size = metadata.len();

    data_stream
        .write_all(format!("RawDataFile {} {} {}\n", raw_data_file, trans_id, file_size).as_bytes())
        .await?;

    log::info!("RawDataFile {} {} {}\n", raw_data_file, trans_id, file_size);

    task_tracker.spawn(
        send_data(
            should_stop.clone(),
            data_stream,
            pcap_file.path().to_path_buf(),
        )
        .await,
    );

    // Handle SIGINT and SIGTERM signals.
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let mut term_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = ctrl_c => {
            should_stop.cancel();
            task_tracker.close();
            task_tracker.wait().await;
        }
        _ = term_signal.recv() => {
            should_stop.cancel();
        }
    }

    Ok(())
}

// Function to connect to the sguil server
async fn sguil_connect(config: PcapAgentConfig) -> io::Result<TlsStream<TcpStream>> {
    let server_host = format!("{}:{}", config.server, config.port);
    let agent_type = &config.agent_type;
    let sensor_name = &config.sensor_name;
    let sensor_net = &config.sensor_net;

    // Connect to the sguil server and set up the TLS stream.
    debug!("Connecting to {}", server_host);
    let stream: TcpStream;

    loop {
        match TcpStream::connect(&server_host).await {
            Ok(connected_stream) => {
                stream = connected_stream;
                break;
            }
            Err(e) => {
                error!("Failed to connect to {}: {}", server_host, e);
                error!("Sguil is down or the server provided is wrong...");
                error!("Retrying in 15 seconds...");
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        };
    }

    let tls_stream = preamble(stream, &config.sguil_version).await?;
    let tls_stream = set_up_tls(tls_stream, &config).await?;
    let stream = register_agent(tls_stream, agent_type, sensor_name, sensor_net).await?;
    info!("Connected to {}", server_host);

    Ok(stream)
}

// Function to get disk space usage
fn disk_space(pcap_dir: String) -> String {
    let disks = Disks::new_with_refreshed_list();
    let disk = disks
        .iter()
        .filter(|disk| pcap_dir.starts_with(disk.mount_point().to_str().unwrap()))
        .max_by_key(|disk| disk.mount_point().to_str().unwrap().len());
    let used_space = disk.unwrap().total_space() - disk.unwrap().available_space();
    let usage = format!(
        "{:.2}%\n",
        (used_space as f64 / disk.unwrap().total_space() as f64) * 100.0
    );
    let usage = format!("{} {}", pcap_dir, usage);
    usage
}

// Function to send pcap file to sguil
async fn send_data(
    should_stop: CancellationToken,
    mut stream: TlsStream<TcpStream>,
    pcap_file: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut file = match File::open(&pcap_file).await {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open pcap file {:?}: {}", pcap_file, e);
                return;
            }
        };
        let mut buffer = vec![0; 4096]; // 4 KB buffer

        while !should_stop.is_cancelled() {
            let read_result = file.read(&mut buffer).await;
            match read_result {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    if let Err(e) = stream.write_all(&buffer[..n]).await {
                        error!("Failed sending pcap file to sguil: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed reading file: {}", e);
                    break;
                }
            }
            // Sguild will drop packets if the file is sent too fast
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        info!("Finished sending pcap file to sguil...");
    })
}

// Function to process agent info command and send response
async fn agent_info(command_tx: mpsc::Sender<String>, config: PcapAgentConfig) {
    let pcap_dir = config.pcap_directory.clone().unwrap();
    match most_recent_file(pcap_dir.as_str()) {
        Ok(time) => {
            let data = format!("LastPcapTime {{{}}}\n", time);
            if let Err(e) = command_tx.send(data.to_string()).await {
                error!("Failed to send last pcap time: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to get most recent pcap file: {}", e);
        }
    }
    let data = format!("DiskReport {}", disk_space(pcap_dir));
    if let Err(e) = command_tx.send(data.to_string()).await {
        error!("Failed to send disk report: {}", e);
    }
}
