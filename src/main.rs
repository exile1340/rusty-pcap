use std::borrow::Borrow;
use pcap::Device;
use etherparse::SlicedPacket;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use pcap_file::pcap::{PcapReader, PcapParser, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet as pnet_packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::PrimitiveValues;
use chrono::{DateTime, Utc};
use std::time::{UNIX_EPOCH, Duration};

fn packet_time(pcap: Packet) -> (String, Packet)  {
    let full_time = pcap.header.ts_sec.to_string() + &*pcap.header.ts_nsec.to_string();
    let d = UNIX_EPOCH + Duration::from_nanos(full_time.parse::<u64>().unwrap());
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%H:%M:%S.%6f").to_string();
    return (timestamp_str, pcap);
}

fn print_packet(pcap: Packet) {
    //Combine seconds and nanoseconds from packet to get full timestamp and print time to screen
    let time_parse = packet_time(pcap);
    print!("{} ", time_parse.0);
    let pcap = time_parse.1;

    let ethernet_packet = EthernetPacket::new(&pcap.data).unwrap();

    let eth_packet = ethernet_packet.get_ethertype();

    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            print!("IP ");
            let v4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
            match v4_packet.get_next_level_protocol() {
                IpNextHeaderProtocol(17) => {
                    let udp_packet = UdpPacket::new(v4_packet.payload()).unwrap();
                    println!("{}:{} > {}:{}", v4_packet.get_source(), udp_packet.get_source(), v4_packet.get_destination(), udp_packet.get_destination());
                }
                IpNextHeaderProtocol(6) => {
                    let tcp_packet = TcpPacket::new(v4_packet.payload()).unwrap();
                    println!("{}:{} > {}:{}", v4_packet.get_source(), tcp_packet.get_source(), v4_packet.get_destination(), tcp_packet.get_destination());
                }
                _ => println!("Unknown Transport Type: {:?}", v4_packet.get_next_level_protocol()),
            }

        }
        EtherTypes::Ipv6 => {
            print!("IP6");
            let v6_packet = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
            match v6_packet.get_next_header() {
                IpNextHeaderProtocol(17) => {
                    let udp_packet = UdpPacket::new(v6_packet.payload()).unwrap();
                    println!("{}.{} > {}.{}", v6_packet.get_source(), udp_packet.get_source(), v6_packet.get_destination(), udp_packet.get_destination());
                }
                IpNextHeaderProtocol(6) => {
                    let tcp_packet = TcpPacket::new(v6_packet.payload()).unwrap();
                    println!("{}.{} > {}.{}", v6_packet.get_source(), tcp_packet.get_source(), v6_packet.get_destination(), tcp_packet.get_destination());
                }
                _ => println!("Unknown Transport Type: {:?}", v6_packet.get_next_header()),
            }
        }
        EtherTypes::Arp => {
            println!("ARP");
        }
        _ => println!("Unknown Type: {:?}", eth_packet),
    }
}

fn main() {
    println!("Hello, world!");

    let file_in = File::open("test.pcap").expect("Error opening file");
    let pcap_reader = PcapReader::new(file_in).unwrap();

    for pcap in pcap_reader {
        let pcap: Packet = pcap.unwrap();
        //println!("{:?}", pcap);
        print_packet(pcap);
    }

    /*let mut cap= Device::lookup().unwrap().open().unwrap();
    while let Ok(packet) = cap.next() {
        println!("received packet! {:?}", packet);
        match SlicedPacket::from_ethernet(&packet) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                println!("link: {:?}", value.link);
                println!("vlan: {:?}", value.vlan);
                println!("ip: {:?}", value.ip);
                println!("transport: {:?}", value.transport);
            }
        }
    }*/
}
