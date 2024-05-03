use crate::api_server;
use crate::PcapFilter;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, error, info, warn};
use native_tls::TlsConnector as NativeTlsConnector;
use serde::Deserialize;
use serde::Serialize;
use std::io;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Sender};
use tokio_native_tls::{TlsConnector, TlsStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::search_pcap;

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
}

#[derive(Debug)]
enum SguilCommand {
    PING,
    PONG,
    RawDataRequest,
}

impl FromStr for SguilCommand {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PING" => Ok(SguilCommand::PING),
            "PONG" => Ok(SguilCommand::PONG),
            "RawDataRequest" => Ok(SguilCommand::RawDataRequest),
            _ => Err(()),
        }
    }
}

pub async fn pcap_agent(config: PcapAgentConfig) -> io::Result<()> {
    let server_host = format!("{}:{}", config.server, config.port);
    let agent_type = &config.agent_type;
    let sensor_name = &config.sensor_name;
    let sensor_net = &config.sensor_net;
    let ping_interval = config.ping_interval;

    let should_stop = CancellationToken::new();
    let task_tracker = TaskTracker::new();

    let mut connected = false;

    // Connect to the sguil server and set up the TLS stream.
    debug!("Connecting to {}", server_host);
    let mut stream: TcpStream;

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
                sleep(Duration::from_secs(15));
            }
        };
    }

    let tls_stream = preamble(stream, &config.sguil_version).await?;
    let tls_stream = set_up_tls(tls_stream, &config.server, &config.port).await?;
    let stream = register_agent(tls_stream, agent_type, sensor_name, sensor_net).await?;
    info!("Connected to {}", server_host);

    let (stream_reader, stream_writer) = tokio::io::split(stream);

    // Create channels for communication between tasks.
    let (reader_tx, command_rx) = mpsc::channel::<String>(100);
    let (command_tx, writer_rx) = mpsc::channel::<String>(100);

    // Spawn the reader, writer, command processing, and ping tasks.
    task_tracker.spawn(spawn_reader_task(should_stop.clone(), stream_reader, reader_tx).await);
    task_tracker.spawn(ping_task(should_stop.clone(), command_tx.clone(), ping_interval).await);
    task_tracker.spawn(writer_task(should_stop.clone(), stream_writer, writer_rx).await);
    task_tracker.spawn(command_task(should_stop.clone(), command_rx, command_tx, config).await);

    // Handle SIGINT and SIGTERM signals.
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let mut term_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
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
    }

    Ok(())
}

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
        sleep(Duration::from_millis(15000));
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

    let mut reader = tokio::io::BufReader::new(stream);
    let response = read_line(&mut reader).await?;
    debug!("Received response: {}", response.trim());
    return Ok(reader.into_inner());
}

async fn set_up_tls(
    tcp_stream: TcpStream,
    server: &str,
    port: &str,
) -> io::Result<TlsStream<TcpStream>> {
    let server_host: String = format!("{}:{}", server, port);
    let mut builder = NativeTlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    let connector = builder.build().unwrap();
    let connector = TlsConnector::from(connector);

    match connector.connect(&server_host, tcp_stream).await {
        Ok(stream) => {
            debug!("TLS connection established...");
            Ok(stream)
        }
        Err(e) => {
            error!("Failed TLS connection: {}", e);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed TLS connection: {}", e),
            ))
        }
    }
}

async fn spawn_reader_task(
    should_stop: CancellationToken,
    stream_reader: tokio::io::ReadHalf<TlsStream<TcpStream>>,
    reader_tx: Sender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stream_reader);
        loop {
            let mut buffer = String::new();
            tokio::select! {
            result = reader.read_line(&mut buffer) => {
                    match result {
                        Ok(_) => {
                            let _ = reader_tx.send(buffer).await;
                        }
                        Err(e) => {
                            error!("Failed to read from stream: {}", e);
                            break;
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

async fn ping_task(
    should_stop: CancellationToken,
    command_tx: Sender<String>,
    ping_interval: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(ping_interval)) => {
                    let data = "PING\n";
                    if let Err(e) = command_tx.send(data.to_string()).await {
                        error!("Failed to send ping: {}", e);
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

async fn writer_task(
    should_stop: CancellationToken,
    mut stream_writer: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    mut writer_rx: mpsc::Receiver<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(message) = writer_rx.recv() => {
                    info!("Sending: {}", message.trim());
                    if let Err(e) = stream_writer.write_all(message.as_bytes()).await {
                        error!("Failed to write to stream: {}", e);
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

async fn command_task(
    should_stop: CancellationToken,
    mut command_rx: mpsc::Receiver<String>,
    command_tx: mpsc::Sender<String>,
    config: PcapAgentConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(command) = command_rx.recv() => {
                    info!("Received: {}", command.trim());
                    let re = regex::Regex::new(r#"(\{[^}]*\}|\S+)"#).unwrap();
                    let request: Vec<&str> = re.find_iter(command.trim())
                           .map(|mat| mat.as_str())
                           .collect();
                    //let request = command.trim().split(' ').collect::<Vec<&str>>();
                    let command = request[0].parse::<SguilCommand>().unwrap();
                    let response = process_command(command, config.clone(), request).await;
                    if response.is_some() {
                        let _ = command_tx.send(response.unwrap()).await;
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

async fn read_line(reader: &mut (impl AsyncBufReadExt + Unpin)) -> std::io::Result<String> {
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    Ok(buffer)
}

async fn process_command(
    command: SguilCommand,
    config: PcapAgentConfig,
    request: std::vec::Vec<&str>,
) -> Option<String> {
    debug!("Processing command: {:?}", command);
    match command {
        SguilCommand::PING => Some("PONG\n".to_string()),
        SguilCommand::PONG => None,
        SguilCommand::RawDataRequest => {
            debug!("Received RawDataRequest");
            xscript_request(request, config).await;
            //Some("XscriptResponse\n".to_string())
            None
        }
    }
}

async fn xscript_request(request: std::vec::Vec<&str>, config: PcapAgentConfig) -> io::Result<()> {
    //socketID TRANS_ID sensor timestamp srcIP dstIP srcPort dstPort proto rawDataFileName type
    //Sending pillarofautumn: RawDataRequest 11 pillarofautumn 2024-04-25 20:58:47 142.250.191.195 10.1.3.124 34696 6 10.1.3.124:34696_142.250.191.195:2561-6.raw xscript
    debug!("Processing XscriptRequest");
    let trans_id = request[1];
    let sensor = request[2];

    let timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDateTime::parse_from_str(request[3], "{%Y-%m-%d %H:%M:%S}")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse timestamp"))?,
        Utc,
    )
    .to_rfc3339();

    let src_ip = request[4];
    let dst_ip = request[5];
    let src_port = request[6];
    let dst_port = request[7];
    let proto = request[8];
    let raw_data_file = request[9];
    let _type = request[10];

    debug!("Request from Sguil: {:?}", request);
    // Create config for get_pcap
    // Need to improve config handling
    let search_config: crate::Config = crate::Config {
        pcap_directory: Some(config.pcap_directory.unwrap()),
        output_directory: Some(config.output_directory.unwrap()),
        log_level: Some("debug".to_string()),
        enable_server: Some(false),
        search_buffer: Some("30s".to_string()),
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
    let pcap = api_server::get_pcap(pcap_filter, &search_config)
        .await
        .unwrap();

    debug!("Pcap: {:?}", pcap);

    Ok(())
}
