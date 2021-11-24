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

#[derive(StructOpt)]
struct Cli {
    #[structopt(help = "PCAP file to parse", short = "f", long = "file")]
    pcap_file: std::path::PathBuf,

    #[structopt(help = "Output parsed packets to screen", short = "p", long = "print")]
    output: bool,

    #[structopt(help = "IP to filter on", short = "ip", long = "ip")]
    ip: Option<std::net::IpAddr>,

    #[structopt(help = "Source IP to filter on", short = "sip", long = "src_ip")]
    src_ip: Option<std::net::IpAddr>,

    #[structopt(help = "Destination IP to filter on", short = "dip", long = "dest_ip")]
    dest_ip: Option<std::net::IpAddr>,
}

fn packet_time(pcap: &Packet) -> String  {
    let full_time = pcap.header.ts_sec.to_string() + &*pcap.header.ts_nsec.to_string();
    let d = UNIX_EPOCH + Duration::from_nanos(full_time.parse::<u64>().unwrap());
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%H:%M:%S.%6f").to_string();
    return timestamp_str;
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

fn ipv4_parse(pcap: &Packet, ether_packet: &EthernetPacket, args: &Cli) {
    let v4_packet = Ipv4Packet::new(ether_packet.payload()).unwrap();

    // IF IP filter is present, test if the packet  contains that IP, if not return from function
    if args.ip.is_some() {
        if args.ip.unwrap() != v4_packet.get_source() && args.ip.unwrap() != v4_packet.get_destination() {
            return
        }
    }
    match v4_packet.get_next_level_protocol() {
        IpNextHeaderProtocol(17) => {
            udp_parse(&pcap, v4_packet, &args);
        }
        IpNextHeaderProtocol(6) => {
            tcp_parse(&pcap, v4_packet, &args);
        }
        _ => return,
    }
}

fn ipv6_parse(pcap: &Packet, ether_packet: &EthernetPacket, args: &Cli) {
    let v6_packet = Ipv6Packet::new(ether_packet.payload()).unwrap();

    // IF IP filter is present, test if the packet  contains that IP, if not return from function
    if args.ip.is_some() {
        if args.ip.unwrap() != v6_packet.get_source() && args.ip.unwrap() != v6_packet.get_destination() {
            return
        }
    }

    match v6_packet.get_next_header() {
        IpNextHeaderProtocol(17) => {
            udp6_parse(&pcap, v6_packet, args);
        }
        IpNextHeaderProtocol(6) => {
            tcp6_parse(&pcap, v6_packet, args);
        }
        _ => return,
    }
}

fn udp_parse(pcap: &Packet, v4_packet: Ipv4Packet, args: &Cli) {
    let udp_packet = UdpPacket::new(&v4_packet.payload()).unwrap();
    if args.output {
        println!("{} IP {}:{} > {}:{}: udp {}", packet_time(&pcap), v4_packet.get_source(), udp_packet.get_source(), v4_packet.get_destination(), udp_packet.get_destination(), udp_packet.get_length().to_string());
    }
}

fn tcp_parse(pcap: &Packet, v4_packet: Ipv4Packet, args: &Cli) {
    let tcp_packet = TcpPacket::new(&v4_packet.payload()).unwrap();
    if args.output {
        println!("{} IP {}:{} > {}:{}: Flags [{}]", packet_time(&pcap), v4_packet.get_source(), tcp_packet.get_source(), v4_packet.get_destination(), tcp_packet.get_destination(), tcp_flags(tcp_packet.get_flags()));
    }
}

fn udp6_parse(pcap: &Packet, v6_packet: Ipv6Packet, args: &Cli) {
    let udp_packet = UdpPacket::new(&v6_packet.payload()).unwrap();
    if args.output {
        println!("{} IP6 {}:{} > {}:{}: udp {}", packet_time(&pcap), v6_packet.get_source(), udp_packet.get_source(), v6_packet.get_destination(), udp_packet.get_destination(), udp_packet.get_length().to_string());
    }
}

fn tcp6_parse(pcap: &Packet, v6_packet: Ipv6Packet, args: &Cli) {
    let tcp_packet = TcpPacket::new(&v6_packet.payload()).unwrap();
    if args.output {
        println!("{} IP6 {}:{} > {}:{}: Flags [{}]", packet_time(&pcap), v6_packet.get_source(), tcp_packet.get_source(), v6_packet.get_destination(), tcp_packet.get_destination(), tcp_flags(tcp_packet.get_flags()));
    }
}

fn packet_parse(pcap: Packet, args: &Cli) {
    //Combine seconds and nanoseconds from packet to get full timestamp and print time to screen
    let mut print_output = "".to_string();
    let time_parse = packet_time(&pcap);
    print_output.push_str(&time_parse);

    let ethernet_packet = EthernetPacket::new(&pcap.data).unwrap();
    let eth_packet = ethernet_packet.get_ethertype();

    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            ipv4_parse(&pcap, &ethernet_packet, args);
        }
        EtherTypes::Ipv6 => {
            ipv6_parse(&pcap, &ethernet_packet, args);
        }
        EtherTypes::Arp => {
            print_output.push_str(&format!(" ARP: {:?}", ethernet_packet));
        }
        EtherType(39) => {
            print_output.push_str(&format!(" STP: {:?}", ethernet_packet));
        }
        _ => print_output.push_str(&format!(" Unknown Type: {:?}", eth_packet)),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args = Cli::from_args();
    let file_in = File::open(&args.pcap_file)?;
    let pcap_reader = PcapReader::new(file_in)?;

    for pcap in pcap_reader {
        let pcap: Packet = pcap.unwrap();
        packet_parse(pcap, &args);
    }

    Ok(())

}
