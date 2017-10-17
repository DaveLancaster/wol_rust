extern crate getopts;

use std::{env, process};
use getopts::Options;
use std::net::{SocketAddrV4, Ipv4Addr};

mod wol {
    extern crate regex;

    use wol::regex::Regex;

    use std::error::Error;
    use std::str::FromStr;
    use std::net::{UdpSocket, SocketAddrV4, Ipv4Addr};

    #[cfg(test)]
    mod test {
        use super::{build_packet, send_packet, Mac, ParseError};
        use std::net::{SocketAddrV4, Ipv4Addr};

        #[test]
        fn can_parse_valid_mac() {
            assert_eq!("ff:ff:ff:ff:ff:ff".parse::<Mac>().unwrap(),
                       Mac(255, 255, 255, 255, 255, 255));
            assert_eq!("FF:FF:FF:FF:FF:FF".parse::<Mac>().unwrap(),
                       Mac(255, 255, 255, 255, 255, 255));
            assert_eq!("00:00:00:00:00:00".parse::<Mac>().unwrap(),
                       Mac(0, 0, 0, 0, 0, 0));
        }

        #[test]
        fn return_error_for_invalid_mac() {
            let macs = vec![":::::", "ff:ff:ff:ff:ff:fg", "ff:ff:ff:ff:ff:ff:ff"];
            for m in macs {
                match m.parse::<Mac>() {
                    Err(e) => assert_eq!(e, ParseError::InvalidInput),
                    Ok(_) => unreachable!(),
                };
            }
        }

        #[test]
        fn can_build_magic_packet() {
            let mac: Mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();
            assert_eq!(build_packet(&mac).unwrap().is_empty(), false);
            assert_eq!(build_packet(&mac).unwrap().len(), 102);
            assert_eq!(build_packet(&mac).unwrap(), vec![255; 102]);
        }

        #[test]
        fn can_send_packet_loopback() {
            let raddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9);
            assert_eq!(send_packet(&vec![0xff; 102], &raddr).unwrap(), true);
        }
    }

    #[derive(Debug)]
    pub enum WolError {
        InvalidBufferLength,
        InvalidPacketSize,
    }

    #[derive(Debug, PartialEq)]
    pub enum ParseError {
        FailedConversion,
        InvalidInput,
        InvalidLength,
    }

    #[derive(Debug, PartialEq)]
    pub struct Mac(u8, u8, u8, u8, u8, u8);

    impl Mac {
        pub fn new(a: (u8, u8, u8, u8, u8, u8)) -> Mac {
            Mac(a.0, a.1, a.2, a.3, a.4, a.5)
        }

        fn as_bytes(&self) -> [u8; 6] {
            [self.0, self.1, self.2, self.3, self.4, self.5]
        }
    }

    impl FromStr for Mac {
        type Err = ParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let valid_mac = {
                Regex::new("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$").unwrap()
            };

            if valid_mac.is_match(s) {
                match s.split(':')
                    .map(|e| u8::from_str_radix(e, 16))
                    .collect::<Result<Vec<_>, _>>() {
                    Ok(r) => {
                        if r.len() == 6 {
                            Ok(Mac::new((r[0], r[1], r[2], r[3], r[4], r[5])))
                        } else {
                            Err(ParseError::InvalidLength)
                        }
                    }
                    Err(_) => Err(ParseError::FailedConversion),
                }
            } else {
                Err(ParseError::InvalidInput)
            }
        }
    }

    pub fn build_packet(mac: &Mac) -> Result<Vec<u8>, WolError> {
        let mut packet = vec![0xff; 6];
        let payload = mac.as_bytes();

        match payload.len() {
            6 => {
                for _ in 0..16 {
                    packet.extend_from_slice(&payload);
                }
            }
            _ => return Err(WolError::InvalidBufferLength),
        }

        match packet.len() {
            102 => return Ok(packet),
            _ => return Err(WolError::InvalidPacketSize),
        }
    }

    pub fn send_packet(p: &[u8], r: &SocketAddrV4) -> Result<bool, Box<Error>> {
        let laddr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let socket = try!(UdpSocket::bind(laddr));

        try!(socket.send_to(&p[0..102], r));

        Ok(true)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts: Options = Options::new();

    opts.optopt("m", "mac", "MAC address in the form FF:FF:FF:FF:FF:FF", "")
        .optopt("b", "bcast", "broadcast address", "")
        .optflag("h", "help", "display this help");

    let name = args[0].clone();

    let usage = format!("Usage: {}", opts.usage(&(name + " [options]")));

    let exit = |msg: &str, code: i32| -> ! {
        println!("{}", msg);
        process::exit(code);
    };

    let matches = opts.parse(&args[1..])
        .unwrap_or_else(|e| exit(&format!("could not parse args: {:?}", e), 1));

    if matches.opt_present("help") {
        exit(&usage, 0);
    }

    let mac: wol::Mac = match matches.opt_str("mac") {
        Some(m) => {
            m.parse()
                .unwrap_or_else(|e| exit(&format!("could not parse mac: {:?}", e), 1))
        }
        None => exit(&usage, 0),
    };

    let bcast: Ipv4Addr = match matches.opt_str("bcast") {
        Some(b) => {
            b.parse()
                .unwrap_or_else(|e| exit(&format!("could not parse ip: {:?}", e), 1))
        }
        None => exit(&usage, 0),
    };

    let magic_packet = wol::build_packet(&mac)
        .unwrap_or_else(|e| exit(&format!("could not build packet: {:?}", e), 1));

    let raddr = SocketAddrV4::new(bcast, 9);

    match wol::send_packet(&magic_packet, &raddr) {
        Ok(_) => println!("packet sent Ok"),
        Err(e) => exit(&format!("could not send request: {:?}", e), 1),
    };
}
