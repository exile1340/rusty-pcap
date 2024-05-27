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
 * This file contains the code that handles the pcap search filter(s) creation.
 */

// Import necessary libraries and modules
use crate::PcapFilter;
use chrono::{DateTime, Utc};
use pcap_file::pcap::PcapPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet as pnet_packet;
use std::time::UNIX_EPOCH;

fn _packet_time(pcap: &PcapPacket) -> String {
    let full_time = pcap.timestamp;
    let d = UNIX_EPOCH + full_time;
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%H:%M:%S.%6f").to_string();
    timestamp_str
}

fn ipv4_parse(ip_packet: Ipv4Packet, args: &PcapFilter) -> bool {
    let v4_packet = ip_packet;

    // for the first ip in args.ip, check if it is equal to the source or destination of the packet
    // if it is not, return false
    // if it is, continue to the second ip in args.ip

    if let Some(ip) = &args.ip {
        // can't have more than 2 ips
        if ip.len() > 2 {
            return false;
        } else if ip.len() == 1 {
            if ip[0] != v4_packet.get_source() && ip[0] != v4_packet.get_destination() {
                return false;
            }
        } else if ip.len() == 2 {
            if ip[0] != v4_packet.get_source() && ip[0] != v4_packet.get_destination() {
                return false;
            }
            if ip[1] != v4_packet.get_source() && ip[1] != v4_packet.get_destination() {
                return false;
            }
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
        IpNextHeaderProtocol(17) => udp_parse(v4_packet, args),
        IpNextHeaderProtocol(6) => tcp_parse(v4_packet, args),
        IpNextHeaderProtocol(1) => icmp_parse(args),
        _ => false,
        //_ => args.port.is_none() && args.src_port.is_none() && args.dest_port.is_none(),
    }
}

fn ipv6_parse(ip_packet: Ipv6Packet, args: &PcapFilter) -> bool {
    let v6_packet = ip_packet;

    if let Some(ip) = &args.ip {
        // can't have more than 2 ips
        if ip.len() > 2 {
            return false;
        } else if ip.len() == 1 {
            if ip[0] != v6_packet.get_source() && ip[0] != v6_packet.get_destination() {
                return false;
            }
        } else if ip.len() == 2 {
            if ip[0] != v6_packet.get_source() && ip[0] != v6_packet.get_destination() {
                return false;
            }
            if ip[1] != v6_packet.get_source() && ip[1] != v6_packet.get_destination() {
                return false;
            }
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
        IpNextHeaderProtocol(1) => icmp_parse(args),
        _ => args.port.is_none() && args.src_port.is_none() && args.dest_port.is_none(),
    }
}

fn icmp_parse(args: &PcapFilter) -> bool {
    args.port.is_none() && args.src_port.is_none() && args.dest_port.is_none()
}

fn udp_parse(v4_packet: Ipv4Packet, args: &PcapFilter) -> bool {
    let udp_packet = UdpPacket::new(v4_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        if !match port.len() {
            1 => port[0] == udp_packet.get_source() || port[0] == udp_packet.get_destination(),
            2 => {
                port.contains(&udp_packet.get_source())
                    && port.contains(&udp_packet.get_destination())
            }
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
    let tcp_packet = TcpPacket::new(v4_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        match port.len() {
            1 => {
                let tcp_port = port[0];
                if tcp_port != tcp_packet.get_source() && tcp_port != tcp_packet.get_destination() {
                    return false;
                }
            }
            2 => {
                if !port.contains(&tcp_packet.get_source())
                    || !port.contains(&tcp_packet.get_destination())
                {
                    return false;
                }
            }
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
    let udp_packet = UdpPacket::new(v6_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        match port.len() {
            1 => {
                let udp_port = port[0];
                if udp_port != udp_packet.get_source() && udp_port != udp_packet.get_destination() {
                    return false;
                }
            }
            2 => {
                if !port.contains(&udp_packet.get_source())
                    || !port.contains(&udp_packet.get_destination())
                {
                    return false;
                }
            }
            _ => return false, // Invalid number of ports provided
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
    let tcp_packet = TcpPacket::new(v6_packet.payload()).unwrap();

    if let Some(port) = &args.port {
        match port.len() {
            1 => {
                let tcp_port = port[0];
                if tcp_port != tcp_packet.get_source() && tcp_port != tcp_packet.get_destination() {
                    return false;
                }
            }
            2 => {
                if !port.contains(&tcp_packet.get_source())
                    || !port.contains(&tcp_packet.get_destination())
                {
                    return false;
                }
            }
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
        EtherTypes::Ipv4 => ipv4_parse(Ipv4Packet::new(ethernet_packet.payload()).unwrap(), args),
        EtherTypes::Ipv6 => ipv6_parse(Ipv6Packet::new(ethernet_packet.payload()).unwrap(), args),
        EtherTypes::Vlan => {
            // Parse the VLAN header
            let vlan_packet = VlanPacket::new(ethernet_packet.payload()).unwrap();
            let vlan_ethertype = vlan_packet.get_ethertype();

            match vlan_ethertype {
                EtherTypes::Ipv4 => {
                    ipv4_parse(Ipv4Packet::new(vlan_packet.payload()).unwrap(), args)
                }
                EtherTypes::Ipv6 => {
                    ipv6_parse(Ipv6Packet::new(vlan_packet.payload()).unwrap(), args)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::Packet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn create_ipv4_udp_packet(
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        src_port: u16,
        dest_port: u16,
    ) -> Vec<u8> {
        let mut ethernet_buffer = [0u8; 42]; // Ethernet header (14) + IPv4 header (20) + UDP header (8)
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);

        // Increase the buffer size to accommodate both the IPv4 header and UDP header
        let mut ipv4_udp_buffer = [0u8; 28]; // IPv4 header (20) + UDP header (8)
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_udp_buffer).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(28);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(src_ip);
        ipv4_packet.set_destination(dest_ip);

        let mut udp_buffer = [0u8; 8];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(src_port);
        udp_packet.set_destination(dest_port);
        udp_packet.set_length(8);

        // Set the UDP header as the payload of the IPv4 packet
        ipv4_packet.set_payload(udp_packet.packet());

        // Set the IPv4 packet (with UDP payload) as the payload of the Ethernet packet
        ethernet_packet.set_payload(ipv4_packet.packet());

        ethernet_buffer.to_vec()
    }

    #[test]
    fn test_ipv4_parse_with_udp_packet() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dest_ip = Ipv4Addr::new(10, 0, 0, 1);
        let src_port = 12345;
        let dest_port = 80;
        let packet_data = create_ipv4_udp_packet(src_ip, dest_ip, src_port, dest_port);
        let ethernet_packet = EthernetPacket::new(&packet_data).unwrap();

        let filter = PcapFilter {
            ip: Some(vec![
                std::net::IpAddr::V4(src_ip),
                std::net::IpAddr::V4(dest_ip),
            ]),
            port: Some(vec![src_port, dest_port]),
            src_ip: Some(std::net::IpAddr::V4(src_ip)),
            src_port: Some(src_port),
            dest_ip: Some(std::net::IpAddr::V4(dest_ip)),
            dest_port: Some(dest_port),
            timestamp: None,
            buffer: None,
        };

        assert!(ipv4_parse(
            Ipv4Packet::new(ethernet_packet.payload()).unwrap(),
            &filter
        ));
    }

    #[test]
    fn test_tcp_parse() {
        let mut ipv4_buffer = [0u8; 40]; // 20 bytes for IPv4 header, 20 bytes for TCP header
        let mut tcp_buffer = [0u8; 20]; // 20 bytes for TCP header

        let source_ip = Ipv4Addr::new(127, 0, 0, 1);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 1);
        let source_port = 8080;
        let destination_port = 80;

        // Set up the IPv4 packet
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer[..]).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(40);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(destination_ip);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        // Set up the TCP packet
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(destination_port);

        // Combine the IPv4 and TCP packets
        ipv4_packet.set_payload(tcp_packet.packet());

        // Set up the PcapFilter
        let filter = PcapFilter {
            ip: Some(vec![source_ip.into(), destination_ip.into()]),
            port: Some(vec![source_port, destination_port]),
            src_ip: Some(source_ip.into()),
            src_port: Some(source_port),
            dest_ip: Some(destination_ip.into()),
            dest_port: Some(destination_port),
            timestamp: None,
            buffer: None,
        };

        // Test the tcp_parse function
        assert!(tcp_parse(
            Ipv4Packet::new(ipv4_packet.packet()).unwrap(),
            &filter
        ));
    }

    #[test]
    fn test_tcp6_parse() {
        let mut ipv6_buffer = [0u8; 60]; // IPv6 header (40) + TCP header (20)
        let mut tcp_buffer = [0u8; 20]; // TCP header

        let source_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let destination_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let source_port = 8080;
        let destination_port = 80;

        // Set up the IPv6 packet
        let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
        ipv6_packet.set_version(6);
        ipv6_packet.set_payload_length(20); // TCP header
        ipv6_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ipv6_packet.set_source(source_ip);
        ipv6_packet.set_destination(destination_ip);

        // Set up the TCP packet
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(destination_port);

        // Combine the IPv6 and TCP packets
        ipv6_packet.set_payload(tcp_packet.packet());

        // Set up the PcapFilter
        let filter = PcapFilter {
            ip: Some(vec![source_ip.into(), destination_ip.into()]),
            port: Some(vec![source_port, destination_port]),
            src_ip: Some(source_ip.into()),
            src_port: Some(source_port),
            dest_ip: Some(destination_ip.into()),
            dest_port: Some(destination_port),
            timestamp: None,
            buffer: None,
        };

        // Test the tcp6_parse function
        assert!(tcp6_parse(
            Ipv6Packet::new(ipv6_packet.packet()).unwrap(),
            &filter
        ));
    }

    #[test]
    fn test_ipv6_parse_with_udp_packet() {
        let src_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dest_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let src_port = 1234;
        let dest_port = 5678;

        let ether_packet = create_ipv6_udp_packet(src_ip, dest_ip, src_port, dest_port);
        let ipv6_packet = EthernetPacket::new(&ether_packet).unwrap();
        let args = PcapFilter {
            ip: Some(vec![IpAddr::V6(src_ip), IpAddr::V6(dest_ip)]),
            port: Some(vec![src_port, dest_port]),
            src_ip: Some(IpAddr::V6(src_ip)),
            src_port: Some(src_port),
            dest_ip: Some(IpAddr::V6(dest_ip)),
            dest_port: Some(dest_port),
            timestamp: None,
            buffer: None,
        };

        assert!(ipv6_parse(
            Ipv6Packet::new(ipv6_packet.payload()).unwrap(),
            &args
        ));
    }

    #[test]
    fn test_udp6_parse() {
        let src_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dest_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let src_port = 1234;
        let dest_port = 5678;

        let ipv6_packet = create_ipv6_udp_packet(src_ip, dest_ip, src_port, dest_port);

        let args = PcapFilter {
            ip: Some(vec![IpAddr::V6(src_ip), IpAddr::V6(dest_ip)]),
            port: Some(vec![src_port, dest_port]),
            src_ip: Some(IpAddr::V6(src_ip)),
            src_port: Some(src_port),
            dest_ip: Some(IpAddr::V6(dest_ip)),
            dest_port: Some(dest_port),
            timestamp: None,
            buffer: None,
        };

        assert!(udp6_parse(
            Ipv6Packet::new(&ipv6_packet[14..]).unwrap(),
            &args
        ));
    }

    fn create_ipv6_udp_packet(
        src_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        src_port: u16,
        dest_port: u16,
    ) -> Vec<u8> {
        let mut ethernet_buffer = [0u8; 62]; // Ethernet header (14) + IPv6 header (40) + UDP header (8)
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6_buffer = [0u8; 48]; // IPv6 header (40) + UDP header (8)
        let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
        ipv6_packet.set_version(6);
        ipv6_packet.set_payload_length(8);
        ipv6_packet.set_next_header(IpNextHeaderProtocols::Udp);
        ipv6_packet.set_source(src_ip);
        ipv6_packet.set_destination(dest_ip);

        let mut udp_buffer = [0u8; 8];
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(src_port);
        udp_packet.set_destination(dest_port);
        udp_packet.set_length(8);

        ipv6_packet.set_payload(udp_packet.packet());
        ethernet_packet.set_payload(ipv6_packet.packet());

        ethernet_buffer.to_vec()
    }
}
