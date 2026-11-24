//! Outbound-only libp2p transport that tunnels TCP connections through a
//! SOCKS5 proxy (RFC 1928, with RFC 1929 username/password authentication).
//!
//! Design constraints (fail closed):
//! - **No local DNS.** Host names from `/dns`, `/dns4`, `/dns6` and `/onion3`
//!   multiaddrs are sent to the proxy verbatim (`ATYP = DOMAINNAME`), so the
//!   proxy performs resolution. Only the proxy's *own* address may be resolved
//!   locally, when it is configured as a host name (normally it is a loopback IP).
//! - **No listening.** [`Socks5Transport::listen_on`] always refuses; inbound
//!   connectivity must come from a relay circuit or an externally configured
//!   tunnel (for example an I2P server tunnel).
//! - **No direct fallback.** Every dial goes to the proxy; if the proxy is down
//!   the dial fails. Hole-punching dials (`Endpoint::Listener` role) are refused
//!   because they would require a direct path.
//! - **I2P mode** only accepts `.i2p` host names, so clearnet destinations are
//!   never handed to an I2P outproxy.

use libp2p::core::transport::{DialOpts, ListenerId, TransportError, TransportEvent};
use libp2p::core::{Endpoint, Transport};
use libp2p::futures::future::{BoxFuture, Pending};
use libp2p::multiaddr::{Multiaddr, Protocol};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default address of the I2P router's SOCKS proxy (i2pd / Java I2P).
pub const DEFAULT_I2P_SOCKS_ADDR: &str = "127.0.0.1:4447";

/// Default time allowed for connecting to the proxy plus the SOCKS handshake.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Which destinations the transport is allowed to request from the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetPolicy {
    /// Any TCP destination (IP literal or host name, resolved by the proxy).
    Any,
    /// Only `*.i2p` host names (I2P SOCKS proxy without an outproxy).
    I2pOnly,
}

/// Parsed SOCKS5 proxy settings.
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Config {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub credentials: Option<(String, String)>,
    pub policy: TargetPolicy,
    pub connect_timeout: Duration,
}

impl std::fmt::Debug for Socks5Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the password.
        f.debug_struct("Socks5Config")
            .field("proxy_host", &self.proxy_host)
            .field("proxy_port", &self.proxy_port)
            .field(
                "username",
                &self.credentials.as_ref().map(|(u, _)| u.as_str()),
            )
            .field("policy", &self.policy)
            .finish()
    }
}

impl Socks5Config {
    /// Parses a proxy setting of the form
    /// `[socks5://|socks5h://][user:pass@]host:port` (IPv6 as `[addr]:port`).
    pub fn parse(setting: &str, policy: TargetPolicy) -> Result<Self, String> {
        let s = setting.trim();
        if s.is_empty() {
            return Err("proxy address is empty".into());
        }
        let s = s
            .strip_prefix("socks5h://")
            .or_else(|| s.strip_prefix("socks5://"))
            .unwrap_or(s);
        if s.contains("://") {
            return Err(format!(
                "unsupported proxy scheme in {setting:?}; expected socks5://host:port"
            ));
        }
        let (credentials, hostport) = match s.rsplit_once('@') {
            Some((creds, rest)) => {
                let (user, pass) = creds.split_once(':').ok_or_else(|| {
                    "proxy credentials must be written as user:password@host:port".to_string()
                })?;
                if user.is_empty() || user.len() > 255 || pass.len() > 255 {
                    return Err(
                        "proxy username must be 1-255 bytes and password at most 255 bytes".into(),
                    );
                }
                (Some((user.to_string(), pass.to_string())), rest)
            }
            None => (None, s),
        };
        let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
            let (h, p) = rest.split_once("]:").ok_or_else(|| {
                format!("invalid proxy address {hostport:?}; expected [ipv6]:port")
            })?;
            h.parse::<std::net::Ipv6Addr>()
                .map_err(|_| format!("invalid IPv6 proxy host {h:?}"))?;
            (h, p)
        } else {
            let (h, p) = hostport
                .rsplit_once(':')
                .ok_or_else(|| format!("invalid proxy address {hostport:?}; expected host:port"))?;
            if h.contains(':') {
                return Err(format!(
                    "invalid proxy address {hostport:?}; write IPv6 hosts as [addr]:port"
                ));
            }
            (h, p)
        };
        if host.is_empty()
            || host.len() > 253
            || host
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')))
        {
            return Err(format!("invalid proxy host {host:?}"));
        }
        let port: u16 = port
            .parse()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("invalid proxy port {port:?}; expected 1-65535"))?;
        Ok(Self {
            proxy_host: host.to_string(),
            proxy_port: port,
            credentials,
            policy,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        })
    }

    /// Settings for generic SOCKS5 mode: an explicit proxy address is required.
    pub fn socks5_from_setting(proxy_addr: Option<&str>) -> Result<Self, String> {
        match proxy_addr.map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => Self::parse(s, TargetPolicy::Any)
                .map_err(|e| format!("SOCKS5 mode: {e}; refusing to connect directly")),
            None => Err(
                "SOCKS5 mode requires a proxy address (host:port, e.g. 127.0.0.1:9050); \
                 refusing to connect directly"
                    .into(),
            ),
        }
    }

    /// Settings for I2P mode: the router's SOCKS proxy, default `127.0.0.1:4447`.
    pub fn i2p_from_setting(proxy_addr: Option<&str>) -> Result<Self, String> {
        let s = proxy_addr
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_I2P_SOCKS_ADDR);
        Self::parse(s, TargetPolicy::I2pOnly)
            .map_err(|e| format!("I2P mode: {e}; refusing to connect directly"))
    }

    fn proxy_display(&self) -> String {
        if self.proxy_host.contains(':') {
            format!("[{}]:{}", self.proxy_host, self.proxy_port)
        } else {
            format!("{}:{}", self.proxy_host, self.proxy_port)
        }
    }
}

/// Destination requested from the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

/// Extracts a SOCKS destination from `/ip4|ip6|dns|dns4|dns6/<host>/tcp/<port>[/p2p/<id>]`
/// or `/onion3/<addr:port>[/p2p/<id>]`. Anything else (QUIC, websockets,
/// relay circuits, ...) is not handled by this transport.
pub fn target_from_multiaddr(addr: &Multiaddr) -> Option<TargetAddr> {
    let mut iter = addr.iter();
    let target = match iter.next()? {
        Protocol::Onion3(onion) => TargetAddr::Domain(
            format!("{}.onion", base32_lower(onion.hash())),
            onion.port(),
        ),
        first => {
            let port = match iter.next()? {
                Protocol::Tcp(port) => port,
                _ => return None,
            };
            match first {
                Protocol::Ip4(ip) => TargetAddr::Ip(IpAddr::V4(ip), port),
                Protocol::Ip6(ip) => TargetAddr::Ip(IpAddr::V6(ip), port),
                Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => {
                    TargetAddr::Domain(h.to_string(), port)
                }
                _ => return None,
            }
        }
    };
    match iter.next() {
        None => {}
        Some(Protocol::P2p(_)) if iter.next().is_none() => {}
        Some(_) => return None,
    }
    Some(target)
}

fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

fn reply_error(code: u8) -> &'static str {
    match code {
        1 => "general SOCKS server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown SOCKS error",
    }
}

async fn connect_proxy(config: &Socks5Config) -> io::Result<TcpStream> {
    TcpStream::connect((config.proxy_host.as_str(), config.proxy_port))
        .await
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "SOCKS5 proxy {} is unreachable: {e}",
                    config.proxy_display()
                ),
            )
        })
}

/// Method negotiation and optional RFC 1929 authentication.
async fn negotiate(stream: &mut TcpStream, config: &Socks5Config) -> io::Result<()> {
    let greeting: &[u8] = if config.credentials.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream.write_all(greeting).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(other("proxy did not answer with SOCKS version 5"));
    }
    match (reply[1], &config.credentials) {
        (0x00, _) => Ok(()),
        (0x02, Some((user, pass))) => {
            let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
            msg.push(0x01);
            msg.push(user.len() as u8);
            msg.extend_from_slice(user.as_bytes());
            msg.push(pass.len() as u8);
            msg.extend_from_slice(pass.as_bytes());
            stream.write_all(&msg).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(other("SOCKS5 proxy rejected the username/password"));
            }
            Ok(())
        }
        (0xFF, _) => Err(other(
            "SOCKS5 proxy accepted none of the offered authentication methods",
        )),
        (m, _) => Err(other(format!(
            "SOCKS5 proxy selected unsupported authentication method {m:#04x}"
        ))),
    }
}

/// Performs a full SOCKS5 CONNECT on an already-connected proxy stream.
pub async fn socks5_connect(
    stream: &mut TcpStream,
    config: &Socks5Config,
    target: &TargetAddr,
) -> io::Result<()> {
    negotiate(stream, config).await?;

    let mut req = vec![0x05, 0x01, 0x00];
    let port = match target {
        TargetAddr::Ip(IpAddr::V4(ip), port) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
            *port
        }
        TargetAddr::Ip(IpAddr::V6(ip), port) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
            *port
        }
        TargetAddr::Domain(host, port) => {
            if host.is_empty() || host.len() > 255 {
                return Err(other("destination host name must be 1-255 bytes"));
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
            *port
        }
    };
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(other("invalid SOCKS5 reply version"));
    }
    if head[1] != 0x00 {
        return Err(other(format!(
            "SOCKS5 proxy could not connect to the destination: {}",
            reply_error(head[1])
        )));
    }
    // Discard BND.ADDR / BND.PORT.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        t => return Err(other(format!("invalid SOCKS5 reply address type {t}"))),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

/// Connects to the proxy and tunnels to `target`, enforcing the configured
/// timeout. Never touches the destination directly.
pub async fn connect_via_proxy(
    config: &Socks5Config,
    target: &TargetAddr,
) -> io::Result<TcpStream> {
    let fut = async {
        let mut stream = connect_proxy(config).await?;
        let _ = stream.set_nodelay(true);
        socks5_connect(&mut stream, config, target).await?;
        Ok(stream)
    };
    tokio::time::timeout(config.connect_timeout, fut)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out connecting through SOCKS5 proxy {}",
                    config.proxy_display()
                ),
            )
        })?
}

/// Checks that the proxy is reachable and speaks SOCKS5 (method negotiation and
/// authentication only; no CONNECT is issued).
pub async fn probe_proxy(config: &Socks5Config, timeout: Duration) -> io::Result<()> {
    let fut = async {
        let mut stream = connect_proxy(config).await?;
        negotiate(&mut stream, config).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "SOCKS5 proxy {} handshake failed: {e}",
                    config.proxy_display()
                ),
            )
        })
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("SOCKS5 proxy {} did not respond", config.proxy_display()),
        )
    })?
}

/// libp2p transport dialing through a SOCKS5 proxy. Outbound only.
#[derive(Clone, Debug)]
pub struct Socks5Transport {
    config: Arc<Socks5Config>,
}

impl Socks5Transport {
    pub fn new(config: Socks5Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl Transport for Socks5Transport {
    type Output = libp2p::tcp::tokio::TcpStream;
    type Error = io::Error;
    type ListenerUpgrade = Pending<Result<Self::Output, Self::Error>>;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let target = target_from_multiaddr(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;
        if opts.role == Endpoint::Listener {
            return Err(TransportError::Other(other(
                "hole punching needs a direct path and is disabled behind a SOCKS5 proxy",
            )));
        }
        if self.config.policy == TargetPolicy::I2pOnly {
            let is_i2p = matches!(&target, TargetAddr::Domain(h, _)
                if h.to_ascii_lowercase().trim_end_matches('.').ends_with(".i2p"));
            if !is_i2p {
                return Err(TransportError::Other(other(format!(
                    "I2P mode only dials .i2p destinations; refusing {addr}"
                ))));
            }
        }
        let config = self.config.clone();
        Ok(Box::pin(async move {
            let stream = connect_via_proxy(&config, &target).await?;
            tracing::debug!(%addr, "connected through SOCKS5 proxy");
            Ok(libp2p::tcp::tokio::TcpStream(stream))
        }))
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    /// What the mock proxy saw in a CONNECT request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SeenRequest {
        pub atyp: u8,
        pub host: String,
        pub port: u16,
        pub username: Option<String>,
    }

    /// Minimal in-process SOCKS5 server. Host names in `fake_dns` are mapped
    /// to 127.0.0.1 (they do not resolve anywhere else, proving the client
    /// never resolved them itself).
    pub async fn spawn_mock_proxy(
        require_auth: Option<(&'static str, &'static str)>,
        fake_dns: &'static [&'static str],
    ) -> (std::net::SocketAddr, Arc<Mutex<Vec<SeenRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let _ = handle_client(&mut s, require_auth, fake_dns, seen).await;
                });
            }
        });
        (addr, seen)
    }

    async fn handle_client(
        s: &mut TcpStream,
        require_auth: Option<(&str, &str)>,
        fake_dns: &[&str],
        seen: Arc<Mutex<Vec<SeenRequest>>>,
    ) -> io::Result<()> {
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await?;
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await?;
        let mut username = None;
        if let Some((u, p)) = require_auth {
            if !methods.contains(&0x02) {
                s.write_all(&[5, 0xFF]).await?;
                return Ok(());
            }
            s.write_all(&[5, 0x02]).await?;
            let mut ver_len = [0u8; 2];
            s.read_exact(&mut ver_len).await?;
            let mut user = vec![0u8; ver_len[1] as usize];
            s.read_exact(&mut user).await?;
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await?;
            let mut pass = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pass).await?;
            let ok = user == u.as_bytes() && pass == p.as_bytes();
            s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
            if !ok {
                return Ok(());
            }
            username = Some(String::from_utf8_lossy(&user).into_owned());
        } else {
            s.write_all(&[5, 0x00]).await?;
        }
        let mut req = [0u8; 4];
        s.read_exact(&mut req).await?;
        let host = match req[3] {
            1 => {
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await?;
                std::net::Ipv4Addr::from(b).to_string()
            }
            4 => {
                let mut b = [0u8; 16];
                s.read_exact(&mut b).await?;
                std::net::Ipv6Addr::from(b).to_string()
            }
            3 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                let mut b = vec![0u8; l[0] as usize];
                s.read_exact(&mut b).await?;
                String::from_utf8_lossy(&b).into_owned()
            }
            _ => return Ok(()),
        };
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);
        seen.lock().unwrap().push(SeenRequest {
            atyp: req[3],
            host: host.clone(),
            port,
            username,
        });
        let connect_host = if fake_dns.contains(&host.as_str()) {
            "127.0.0.1".to_string()
        } else {
            host
        };
        match TcpStream::connect((connect_host.as_str(), port)).await {
            Ok(mut upstream) => {
                s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                let _ = tokio::io::copy_bidirectional(s, &mut upstream).await;
            }
            Err(_) => {
                s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            }
        }
        Ok(())
    }

    #[test]
    fn parses_valid_proxy_addresses() {
        let c = Socks5Config::parse("127.0.0.1:9050", TargetPolicy::Any).unwrap();
        assert_eq!((c.proxy_host.as_str(), c.proxy_port), ("127.0.0.1", 9050));
        assert!(c.credentials.is_none());
        let c = Socks5Config::parse("socks5h://alice:s3cret@proxy.lan:1080", TargetPolicy::Any)
            .unwrap();
        assert_eq!(c.proxy_host, "proxy.lan");
        assert_eq!(
            c.credentials,
            Some(("alice".to_string(), "s3cret".to_string()))
        );
        assert!(!format!("{c:?}").contains("s3cret"));
        let c = Socks5Config::parse("[::1]:9050", TargetPolicy::Any).unwrap();
        assert_eq!(c.proxy_host, "::1");
    }

    #[test]
    fn rejects_invalid_proxy_addresses() {
        for bad in [
            "",
            "   ",
            "127.0.0.1",
            "127.0.0.1:0",
            "127.0.0.1:70000",
            "127.0.0.1:abc",
            ":9050",
            "::1:9050",
            "http://127.0.0.1:8080",
            "bad host:1080",
            "user@127.0.0.1:1080",
            "/ip4/127.0.0.1/tcp/9050",
        ] {
            assert!(
                Socks5Config::parse(bad, TargetPolicy::Any).is_err(),
                "{bad:?} should be rejected"
            );
        }
        let err = Socks5Config::socks5_from_setting(None).unwrap_err();
        assert!(err.contains("requires a proxy address"), "{err}");
        assert!(Socks5Config::socks5_from_setting(Some("  ")).is_err());
        let i2p = Socks5Config::i2p_from_setting(None).unwrap();
        assert_eq!(i2p.proxy_port, 4447);
        assert_eq!(i2p.policy, TargetPolicy::I2pOnly);
    }

    #[test]
    fn extracts_targets_from_multiaddrs() {
        let m = |s: &str| s.parse::<Multiaddr>().unwrap();
        assert_eq!(
            target_from_multiaddr(&m("/dns4/example.org/tcp/4001")),
            Some(TargetAddr::Domain("example.org".into(), 4001))
        );
        assert_eq!(
            target_from_multiaddr(&m(
                "/ip4/1.2.3.4/tcp/80/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"
            )),
            Some(TargetAddr::Ip("1.2.3.4".parse().unwrap(), 80))
        );
        assert_eq!(
            target_from_multiaddr(&m(
                "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234"
            )),
            Some(TargetAddr::Domain(
                "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion".into(),
                1234
            ))
        );
        assert_eq!(
            target_from_multiaddr(&m("/ip4/1.2.3.4/udp/1/quic-v1")),
            None
        );
        assert_eq!(target_from_multiaddr(&m("/ip4/1.2.3.4/tcp/1/ws")), None);
        assert_eq!(
            target_from_multiaddr(&m(
                "/ip4/1.2.3.4/tcp/1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA/p2p-circuit"
            )),
            None
        );
    }

    #[tokio::test]
    async fn connect_request_carries_hostname_not_resolved_ip() {
        // Target the proxy will forward to.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            s.write_all(b"hello").await.unwrap();
        });

        let (proxy, seen) =
            spawn_mock_proxy(Some(("alice", "pw")), &["peer.alterchat.invalid"]).await;
        let config = Socks5Config::parse(&format!("alice:pw@{proxy}"), TargetPolicy::Any).unwrap();
        let mut stream = connect_via_proxy(
            &config,
            &TargetAddr::Domain("peer.alterchat.invalid".into(), target_port),
        )
        .await
        .expect("proxied connect");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![SeenRequest {
                atyp: 0x03,
                host: "peer.alterchat.invalid".into(),
                port: target_port,
                username: Some("alice".into()),
            }]
        );
    }

    #[tokio::test]
    async fn wrong_credentials_fail() {
        let (proxy, seen) = spawn_mock_proxy(Some(("alice", "pw")), &[]).await;
        let config =
            Socks5Config::parse(&format!("alice:nope@{proxy}"), TargetPolicy::Any).unwrap();
        let err = connect_via_proxy(&config, &TargetAddr::Domain("x.invalid".into(), 1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("username/password"), "{err}");
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn proxy_down_fails_without_direct_attempt() {
        // A reachable "destination" that must never see a connection.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        // A port with nothing listening (bind then drop).
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let config = Socks5Config::parse(&dead_addr.to_string(), TargetPolicy::Any).unwrap();
        let mut transport = Socks5Transport::new(config.clone());
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", target_addr.port())
            .parse()
            .unwrap();
        let dial = transport
            .dial(
                addr,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: libp2p::core::transport::PortUse::New,
                },
            )
            .expect("dial future");
        let err = dial.await.unwrap_err();
        assert!(err.to_string().contains("unreachable"), "{err}");
        assert!(probe_proxy(&config, Duration::from_secs(5)).await.is_err());

        let direct = tokio::time::timeout(Duration::from_millis(300), target.accept()).await;
        assert!(
            direct.is_err(),
            "destination must not be contacted directly"
        );
    }

    #[test]
    fn transport_refuses_listen_hole_punch_and_non_i2p() {
        let config = Socks5Config::parse("127.0.0.1:1", TargetPolicy::Any).unwrap();
        let mut t = Socks5Transport::new(config);
        assert!(matches!(
            t.listen_on(ListenerId::next(), "/ip4/0.0.0.0/tcp/0".parse().unwrap()),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
        let listener_role = DialOpts {
            role: Endpoint::Listener,
            port_use: libp2p::core::transport::PortUse::Reuse,
        };
        assert!(matches!(
            t.dial("/ip4/1.2.3.4/tcp/1".parse().unwrap(), listener_role),
            Err(TransportError::Other(_))
        ));

        let mut i2p = Socks5Transport::new(Socks5Config::i2p_from_setting(None).unwrap());
        let dialer = DialOpts {
            role: Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        };
        assert!(matches!(
            i2p.dial("/ip4/1.2.3.4/tcp/1".parse().unwrap(), dialer),
            Err(TransportError::Other(_))
        ));
        assert!(matches!(
            i2p.dial("/dns/example.org/tcp/1".parse().unwrap(), dialer),
            Err(TransportError::Other(_))
        ));
        assert!(
            i2p.dial(
                "/dns/ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p/tcp/4001"
                    .parse()
                    .unwrap(),
                dialer
            )
            .is_ok()
        );
    }
}
