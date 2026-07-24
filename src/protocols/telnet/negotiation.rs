const TELNET_IAC: u8 = 255;
const TELNET_DONT: u8 = 254;
const TELNET_DO: u8 = 253;
const TELNET_WONT: u8 = 252;
const TELNET_WILL: u8 = 251;

pub fn handle_telnet_negotiation(buf: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == TELNET_IAC && i + 2 < buf.len() {
            match buf[i + 1] {
                TELNET_DO => {
                    response.extend_from_slice(&[TELNET_IAC, TELNET_WONT, buf[i + 2]]);
                }
                TELNET_WILL => {
                    response.extend_from_slice(&[TELNET_IAC, TELNET_DONT, buf[i + 2]]);
                }
                TELNET_DONT | TELNET_WONT => {}
                _ => {}
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    response
}
