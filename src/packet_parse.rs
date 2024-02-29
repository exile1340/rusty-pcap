use pnet::packet::Packet as pnet_packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pcap_file::pcap::PcapPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use chrono::{DateTime, Utc};
use std::time::UNIX_EPOCH;
use crate::write_pcap::PcapFilter;

fn packet_time(pcap: &PcapPacket) -> String  {
    let full_time = pcap.timestamp;
    let d = UNIX_EPOCH + full_time;
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%H:%M:%S.%6f").to_string();
    return timestamp_str;
}

fn ipv4_parse(ether_packet: &EthernetPacket, args: &PcapFilter) -> bool {
    let v4_packet = Ipv4Packet::new(ether_packet.payload()).unwrap();

    // Check if packet contains the IP from args.ip
    if let Some(ips) = &args.ip {
        if !ips.is_empty() && !ips.iter().any(|&ip| ip == v4_packet.get_source() || ip == v4_packet.get_destination()) {
            return false;
        }
    }

    // Check if packet source or destination is equal to args.src_ip
    if let Some(src_ip) = args.src_ip {
        if src_ip != v4_packet.get_source() && src_ip != v4_packet.get_destination() {
            return false;
        }
    }

    // Check if packet destination or source is equal to args.dest_ip
    if let Some(dest_ip) = args.dest_ip {
        if dest_ip != v4_packet.get_destination() && dest_ip != v4_packet.get_source() {
            return false;
        }
    }

    // Depending on the next level protocol, parse the packet accordingly
    match v4_packet.get_next_level_protocol() {
        IpNextHeaderProtocol(17) => udp_parse(v4_packet, &args),
        IpNextHeaderProtocol(6) => tcp_parse(v4_packet, &args),
        IpNextHeaderProtocol(1) => icmp_parse(&args),
        _ => false,
        //_ => args.port.is_none() && args.src_port.is_none() && args.dest_port.is_none(),
    }
}

fn ipv6_parse(ether_packet: &EthernetPacket, args: &PcapFilter) -> bool {
    let v6_packet = Ipv6Packet::new(ether_packet.payload()).unwrap();

    // Check if packet contains the IP from args.ip
    if let Some(ips) = &args.ip {
        if !ips.is_empty() && !ips.iter().any(|&ip| ip == v6_packet.get_source() || ip == v6_packet.get_destination()) {
            return false;
        }
    }

    // Check if packet source or destination is equal to args.src_ip
    if let Some(src_ip) = args.src_ip {
        if src_ip != v6_packet.get_source() && src_ip != v6_packet.get_destination() {
            return false;
        }
    }

    // Check if packet destination or source is equal to args.dest_ip
    if let Some(dest_ip) = args.dest_ip {
        if dest_ip != v6_packet.get_destination() && dest_ip != v6_packet.get_source() {
            return false;
        }
    }

    // Depending on the next header, parse the packet accordingly
    match v6_packet.get_next_header() {
        IpNextHeaderProtocol(17) => udp6_parse(v6_packet, args),
        IpNextHeaderProtocol(6) => tcp6_parse(v6_packet, args),
        IpNextHeaderProtocol(1) => icmp_parse(&args),
        _ => args.port.is_none() && args.src_port.is_none() && args.dest_port.is_none(),
    }
}

fn icmp_parse (args: &PcapFilter) -> bool {
    if args.port.is_none() && args.src_port.is_none() && args.dest_port.is_none() {
        return true
    } else { false }
}

fn udp_parse( v4_packet: Ipv4Packet, args: &PcapFilter) -> bool {
    let udp_packet = UdpPacket::new(&v4_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        if !match port.len() {
            1 => port[0] == udp_packet.get_source() || port[0] == udp_packet.get_destination(),
            2 => port.contains(&udp_packet.get_source()) && port.contains(&udp_packet.get_destination()),
            _ => false,
        } {
            return false;
        }
    }

    if let Some(src_port) = args.src_port {
        if src_port != udp_packet.get_source() {
            return false;
        }
    }

    if let Some(dest_port) = args.dest_port {
        if dest_port != udp_packet.get_destination() {
            return false;
        }
    }
    
    true
}

fn tcp_parse(v4_packet: Ipv4Packet, args: &PcapFilter) -> bool {
    let tcp_packet = TcpPacket::new(&v4_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        match port.len() {
            1 => {
                let tcp_port = port[0];
                if tcp_port != tcp_packet.get_source() && tcp_port != tcp_packet.get_destination() {
                    return false;
                }
            },
            2 => if !port.contains(&tcp_packet.get_source()) || !port.contains(&tcp_packet.get_destination()) {
                    return false;
                },
            _ => return false,
        }
    }

    if let Some(src_port) = args.src_port {
        if src_port != tcp_packet.get_source() {
            return false;
        }
    } else if let Some(dest_port) = args.dest_port {
        if dest_port != tcp_packet.get_destination() {
            return false;
        }
    }

    true
}

fn udp6_parse(v6_packet: Ipv6Packet, args: &PcapFilter) -> bool {
    let udp_packet = UdpPacket::new(&v6_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        match port.len() {
            1 => {
                let udp_port = port[0];
                if udp_port != udp_packet.get_source() && udp_port != udp_packet.get_destination() {
                    return false;
                }
            },
            2 => if !port.contains(&udp_packet.get_source()) || !port.contains(&udp_packet.get_destination()) {
                    return false;
                },
            _ => return false,  // Invalid number of ports provided
        }
    }

    if let Some(src_port) = args.src_port {
        if src_port != udp_packet.get_source() {
            return false;
        }
    }

    if let Some(dest_port) = args.dest_port {
        if dest_port != udp_packet.get_destination() {
            return false;
        }
    }

    true
}

fn tcp6_parse(v6_packet: Ipv6Packet, args: &PcapFilter) -> bool {
    let tcp_packet = TcpPacket::new(&v6_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        match port.len() {
            1 => {
                let tcp_port = port[0];
                if tcp_port != tcp_packet.get_source() && tcp_port != tcp_packet.get_destination() {
                    return false;
                }
            },
            2 => if !port.contains(&tcp_packet.get_source()) || !port.contains(&tcp_packet.get_destination()) {
                    return false;
                },
            _ => return false,
        }
    }

    if let Some(src_port) = args.src_port {
        if src_port != tcp_packet.get_source() {
            return false;
        }
    }

    if let Some(dest_port) = args.dest_port {
        if dest_port != tcp_packet.get_destination() {
            return false;
        }
    }

    true
}

pub fn packet_parse(pcap: &PcapPacket, args: &PcapFilter) -> bool {
    let ethernet_packet = EthernetPacket::new(&pcap.data).unwrap();
    let eth_packet = ethernet_packet.get_ethertype();
    match eth_packet {
        EtherTypes::Ipv4 => ipv4_parse(&ethernet_packet, args),
        EtherTypes::Ipv6 => ipv6_parse(&ethernet_packet, args),
        _ => {
            log::debug!("{} Unknown Type: {:?}", packet_time(&pcap), eth_packet);
            false
        },
    }
}