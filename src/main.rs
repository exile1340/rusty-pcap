use std::fs::File;
use pcap_file::pcap::{PcapReader, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, EtherType};
use pnet::packet::Packet as pnet_packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use chrono::{DateTime, Utc};
use std::time::{UNIX_EPOCH, Duration};
use structopt::StructOpt;
use std::net;

#[derive(StructOpt)]
struct Cli {
    #[structopt(help = "PCAP file to parse", short = "f", long = "file")]
    pcap_file: std::path::PathBuf,

    #[structopt(help = "Output parsed packets to screen", short = "p", long = "print")]
    output: bool,

    #[structopt(help = "IP to filter on", short = "i", long = "ip")]
    ip: Option<std::net::IpAddr>,

}

struct PacketFilter {
    src_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
    src_port: i8,
    dest_port: i8,
}

fn packet_time(pcap: Packet) -> (String, Packet)  {
    let full_time = pcap.header.ts_sec.to_string() + &*pcap.header.ts_nsec.to_string();
    let d = UNIX_EPOCH + Duration::from_nanos(full_time.parse::<u64>().unwrap());
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%H:%M:%S.%6f").to_string();
    return (timestamp_str, pcap);
}

fn tcp_flags(encoded_flags: u16) -> String {
    //let flags = format!("{:b}", encoded_flags);
    let mut flags: String = "".to_string();
    // Ack Flag
    if encoded_flags & (1 << 4) > 0 {
        flags.push_str(".");
    }
    // Push Flag
    if encoded_flags & (1 << 3) > 0 {
        flags.push_str("P");
    }
    // Reset Flag
    if encoded_flags & (1 << 2) > 0 {
        flags.push_str("R");
    }
    // Syn Flag
    if encoded_flags & (1 << 1) > 0 {
        flags.push_str("S");
    }
    // Fin flag
    if encoded_flags & (1 << 0) > 0 {
        flags.push_str("F");
    }
    return format!("{}", flags);
}

fn filter(packet: Packet, query: String) {

}

fn print_packet(pcap: Packet, out: bool) {
    //Combine seconds and nanoseconds from packet to get full timestamp and print time to screen
    let mut print_output = "".to_string();
    let time_parse = packet_time(pcap);
    print_output.push_str(&time_parse.0);
    //print!("{} ", print_output);
    let pcap = time_parse.1;

    let ethernet_packet = EthernetPacket::new(&pcap.data).unwrap();
    let eth_packet = ethernet_packet.get_ethertype();

    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            print_output.push_str(" IP ");
            let v4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
            match v4_packet.get_next_level_protocol() {
                IpNextHeaderProtocol(17) => {
                    let udp_packet = UdpPacket::new(v4_packet.payload()).unwrap();
                    print_output.push_str(&format!("{}:{} > {}:{}: udp {}", v4_packet.get_source(), udp_packet.get_source(), v4_packet.get_destination(), udp_packet.get_destination(), udp_packet.get_length()).to_string());
                }
                IpNextHeaderProtocol(6) => {
                    let tcp_packet = TcpPacket::new(v4_packet.payload()).unwrap();
                    let flags = tcp_flags(tcp_packet.get_flags());
                    print_output.push_str(&format!("{}:{} > {}:{}: Flags [{}]", v4_packet.get_source(), tcp_packet.get_source(), v4_packet.get_destination(), tcp_packet.get_destination(), flags));
                }
                _ => print_output.push_str(&format!("Unknown Transport Type: {:?}", v4_packet.get_next_level_protocol())),
            }

        }
        EtherTypes::Ipv6 => {
            print_output.push_str(" IP6 ");
            let v6_packet = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
            match v6_packet.get_next_header() {
                IpNextHeaderProtocol(17) => {
                    let udp_packet = UdpPacket::new(v6_packet.payload()).unwrap();
                    print_output.push_str(&format!("{}.{} > {}.{}: udp {}", v6_packet.get_source(), udp_packet.get_source(), v6_packet.get_destination(), udp_packet.get_destination(), udp_packet.get_length()));
                }
                IpNextHeaderProtocol(6) => {
                    let tcp_packet = TcpPacket::new(v6_packet.payload()).unwrap();
                    let flags = tcp_flags(tcp_packet.get_flags());
                    print_output.push_str(&format!("{}.{} > {}.{}: Flags [{}]", v6_packet.get_source(), tcp_packet.get_source(), v6_packet.get_destination(), tcp_packet.get_destination(), flags));
                }
                _ => print_output.push_str(&format!("Unknown Transport Type: {:?}", v6_packet.get_next_header())),
            }
        }
        EtherTypes::Arp => {
            print_output.push_str(&format!(" ARP: {:?}", ethernet_packet));
        }
        EtherType(39) => {
            print_output.push_str(&format!(" STP: {:?}", ethernet_packet));
        }
        _ => print_output.push_str(&format!(" Unknown Type: {:?}", eth_packet)),
    }
    if out {
        println!("{}", print_output)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args = Cli::from_args();
    let file_in = File::open(args.pcap_file)?;
    let pcap_reader = PcapReader::new(file_in)?;

    for pcap in pcap_reader {
        let pcap: Packet = pcap.unwrap();
        print_packet(pcap, args.output);
    }
    //println!("{:?}", args.ip.unwrap());
    Ok(())

}
