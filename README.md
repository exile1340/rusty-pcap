# Rusty Pcap

Rusty Pcap is a command-line application written in Rust that recieves a query input for a network flow session, searches through available pcap, and returns the result in a file. It allows users to filter packets based on IP addresses, ports, and timestamps, and can run in either CLI mode or as an API server.

## Features

- Search single or multiple PCAP files
- Filter packets based on IP address, port, and timestamp
- Output parsed packets to the screen
- Control log level for debugging
- Run as an API server

## Installation

To install PCAP Analyzer, you will need to have Rust and Cargo installed on your machine. If you do not have Rust installed, you can install it by following the instructions at [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).

Once Rust is installed, you can clone this repository and build the program with Cargo:

The compiled binary will be located in the `target/release` directory.


## Usage

To use Rusty Pcap, you will need to have a PCAP file to analyze. If you do not have a PCAP file, you can download one from the [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) page.

Once you have a PCAP file, you can use Rusty Pcap to search it. To do this, you will need to run the program with the `--file` flag and specify the path to the PCAP file you want to analyze:

### Filtering Packets

You can filter packets by IP address, port, and timestamp. To filter packets by IP address, use the `--ip` flag and specify the IP address you want to filter by:

```
rusty_pcap --file /path/to/pcap/file --ip 192.168.1.1
```

This will filter the packets and only return packets that have the IP address `192.168.1.1` in either the source or destination field.

To filter packets by port, use the `--port` flag and specify the port you want to filter by:

```
rusty_pcap --file /path/to/pcap/file --port 80
```

This will filter the packets and only return packets that have the port `80` in either the source or destination field.

To filter packets by timestamp, use the `--ts` flag and specify the start of the flow you are searching for. Valid time stamps are RFC 3339 format:

```
rusty_pcap --pcap_dir /path/to/pcaps/ --ip 10.1.1.10 --port 443 --ts 2021-01-01T00:00:00.000Z
```

This will search all files that were created before 2021-01-01T00:00:00.000Z and close after 2021-01-01T00:00:00.000Z. Then it will output a pcap file with the matching flow.


## Running as an API Server

You can also run Rusty Pcap as an API server. To do this, use the `--server` flag

```
rusty_pcap --pcap_dir /path/to/pcaps/ --server
```

This will start the server on port `8000` and you can make requests to it using your preferred HTTP client

Available REST endpoints:

```
/pcap?<pcap_request..>
```

Parameters:
ip, port, src_ip, src_port, dest_ip, dest_port, timestamp, buffer

Example

```
{{base_url}}:8000/pcap?timestamp=2024-02-29T19:41:30.478Z&ip=10.1.1.74&ip=17.253.26.75
```
