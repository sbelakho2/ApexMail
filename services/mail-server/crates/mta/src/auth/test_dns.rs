//! A loopback UDP DNS mock shared by the auth-module tests.
//!
//! Serves authoritative TXT answers (and NXDOMAIN/SERVFAIL) for a
//! caller-supplied rule table, so `verify_bimi` / MTA-STS record discovery
//! and every TXT-flattening helper run against the REAL resolver wire path
//! (query encode → UDP → response decode → `Lookup`) without touching the
//! network or the system resolver.

#![cfg(test)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use trust_dns_resolver::config::NameServerConfig;
use trust_dns_resolver::net::runtime::TokioRuntimeProvider;
use trust_dns_resolver::proto::op::{Message, OpCode, ResponseCode};
use trust_dns_resolver::proto::rr::rdata::TXT;
use trust_dns_resolver::proto::rr::{Name, RData, Record, RecordType};
use trust_dns_resolver::TokioResolver;

/// What the mock answers for one queried name.
#[derive(Clone, Debug)]
pub(crate) enum DnsAnswer {
    /// One TXT record per entry; each entry is one record's character-string
    /// chunks (joined without a separator by real DNS semantics).
    Txt(Vec<Vec<String>>),
    /// PTR hostnames (trailing dot tolerated) for a reverse lookup.
    Ptr(Vec<String>),
    /// Forward A/AAAA addresses for a hostname.
    Ips(Vec<IpAddr>),
    Nxdomain,
    Servfail,
}

/// A running mock DNS server plus a resolver pointed at it.
pub(crate) struct MockDns {
    pub resolver: TokioResolver,
    task: tokio::task::JoinHandle<()>,
    /// Loopback UDP port the mock answers on. Consumers whose DNS stack
    /// cannot reuse `resolver` (e.g. mail-auth's own bundled hickory
    /// resolver, a different crate version) build their own resolver
    /// pointed at this port.
    pub port: u16,
}

impl MockDns {
    /// Spawn the server on a loopback UDP port and return a resolver whose
    /// ONLY nameserver is the mock (deterministic; no system resolver, no
    /// real network — everything stays on 127.0.0.1).
    pub async fn start(rules: HashMap<&'static str, DnsAnswer>) -> Self {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock dns");
        let port = socket.local_addr().expect("port").port();
        let rules = Arc::new(rules);
        let task = tokio::spawn(async move {
            let socket = socket;
            let mut buf = [0u8; 4096];
            loop {
                let (len, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let response = answer(&buf[..len], &rules);
                let bytes = match response.to_vec() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let _ = socket.send_to(&bytes, peer).await;
            }
        });

        let mut nameserver = NameServerConfig::udp(IpAddr::V4(Ipv4Addr::LOCALHOST));
        // Route the single UDP connection at the mock's ephemeral port.
        if let Some(connection) = nameserver.connections.first_mut() {
            connection.port = port;
        }
        let config =
            trust_dns_resolver::config::ResolverConfig::from_parts(None, vec![], vec![nameserver]);
        let mut opts = trust_dns_resolver::config::ResolverOpts::default();
        // Fail fast when a rule is missing: no retries, short timeout, and
        // never fall back to TCP or the system configuration.
        opts.attempts = 1;
        opts.timeout = std::time::Duration::from_millis(500);
        opts.try_tcp_on_error = false;
        opts.cache_size = 0;
        // Same hosts-file guard as [`resolver_at`]: loopback PTRs must reach
        // the mock, never /etc/hosts.
        opts.use_hosts_file = trust_dns_resolver::config::ResolveHosts::Never;
        let resolver = trust_dns_resolver::Resolver::builder_with_config(
            config,
            TokioRuntimeProvider::default(),
        )
        .with_options(opts)
        .build()
        .expect("resolver against mock dns");
        Self {
            resolver,
            task,
            port,
        }
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

/// A workspace resolver pointed at an already-running mock's port — for
/// consumers that construct their resolver independently (the inbound
/// server's EmailAuthenticator injection seam).
pub(crate) fn resolver_at(port: u16) -> TokioResolver {
    let mut nameserver = NameServerConfig::udp(IpAddr::V4(Ipv4Addr::LOCALHOST));
    if let Some(connection) = nameserver.connections.first_mut() {
        connection.port = port;
    }
    let config =
        trust_dns_resolver::config::ResolverConfig::from_parts(None, vec![], vec![nameserver]);
    let mut opts = trust_dns_resolver::config::ResolverOpts::default();
    opts.attempts = 1;
    opts.timeout = std::time::Duration::from_millis(500);
    opts.try_tcp_on_error = false;
    opts.cache_size = 0;
    let mut resolver = trust_dns_resolver::Resolver::builder_with_config(
        config,
        trust_dns_resolver::net::runtime::TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()
    .expect("resolver pointed at the mock port");
    // /etc/hosts maps 127.0.0.1 to "localhost": without this, reverse
    // lookups of loopback IPs are answered from the hosts file and never
    // reach the mock (the ResolveHosts option alone does not cover PTR
    // lookups in hickory 0.26).
    resolver.set_hosts(std::sync::Arc::new(trust_dns_resolver::Hosts::default()));
    resolver
}

/// Build the wire response for one incoming query per the rule table.
fn answer(query_bytes: &[u8], rules: &HashMap<&'static str, DnsAnswer>) -> Message {
    let query = match Message::from_vec(query_bytes) {
        Ok(query) => query,
        Err(_) => Message::error_msg(0, OpCode::Query, ResponseCode::FormErr),
    };
    let id = query.metadata.id;
    let mut response = Message::response(id, OpCode::Query);
    let asked = query.queries.first().cloned();
    if let Some(asked) = asked {
        response.add_query(asked.clone());
        // hickory renders queried names WITH the trailing root dot; rule keys
        // are written without it — compare on the trimmed form and answer
        // with the queried name itself (bit-identical owner name).
        let qname = asked.name().to_lowercase().to_string();
        let qname = qname.strip_suffix('.').unwrap_or(&qname).to_string();
        let rule = rules.get(qname.as_str());
        let name = asked.name().clone();
        match rule {
            Some(DnsAnswer::Txt(records)) if asked.query_type() == RecordType::TXT => {
                response.metadata.response_code = ResponseCode::NoError;
                for chunks in records {
                    let txt = TXT::new(chunks.clone());
                    response.add_answer(Record::from_rdata(name.clone(), 60, RData::TXT(txt)));
                }
            }
            Some(DnsAnswer::Ptr(hosts)) if asked.query_type() == RecordType::PTR => {
                response.metadata.response_code = ResponseCode::NoError;
                for host in hosts {
                    let target = Name::parse(host, None).unwrap_or_else(|_| Name::root());
                    response.add_answer(Record::from_rdata(
                        name.clone(),
                        60,
                        RData::PTR(trust_dns_resolver::proto::rr::rdata::PTR(target)),
                    ));
                }
            }
            Some(DnsAnswer::Ips(addrs))
                if matches!(asked.query_type(), RecordType::A | RecordType::AAAA) =>
            {
                response.metadata.response_code = ResponseCode::NoError;
                for addr in addrs {
                    let rdata = match addr {
                        IpAddr::V4(v4) => RData::A(trust_dns_resolver::proto::rr::rdata::A(*v4)),
                        IpAddr::V6(v6) => {
                            RData::AAAA(trust_dns_resolver::proto::rr::rdata::AAAA(*v6))
                        }
                    };
                    response.add_answer(Record::from_rdata(name.clone(), 60, rdata));
                }
            }
            Some(DnsAnswer::Nxdomain) => {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            // A rule of the wrong type (or no rule at all) answers SERVFAIL:
            // the mock is explicit about what it serves.
            Some(DnsAnswer::Servfail)
            | None
            | Some(DnsAnswer::Txt(_))
            | Some(DnsAnswer::Ptr(_))
            | Some(DnsAnswer::Ips(_)) => {
                response.metadata.response_code = ResponseCode::ServFail;
            }
        }
    } else {
        response.metadata.response_code = ResponseCode::FormErr;
    }
    response
}

#[cfg(test)]
mod temp_diag {
    use super::*;

    #[tokio::test]
    async fn temp_dead_port_lookup() {
        let start = std::time::Instant::now();
        let resolver = resolver_at(1);
        let out = resolver
            .reverse_lookup(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
            .await;
        eprintln!(
            "DBG elapsed={:?} out={:?}",
            start.elapsed(),
            out.map_err(|e| e.to_string())
        );
    }
}
