//! Scripted `DnsProvider` stub for tests: answers from an in-memory record
//! map, never touching the network. Unknown names behave like NXDOMAIN
//! (`Err`); known names without the requested record type return empty data.

use crate::dns_provider::{DnsFuture, DnsProvider};
use apexmail_dns_resolver::records::{DkimRecord, DmarcPolicy, MxRecord, SpfRecord};
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct StubDns {
    pub txt: HashMap<String, Vec<String>>,
    pub mx: HashMap<String, Vec<MxRecord>>,
    pub spf: HashMap<String, Option<SpfRecord>>,
    pub dmarc: HashMap<String, Option<DmarcPolicy>>,
    pub dkim: HashMap<String, Option<DkimRecord>>,
    pub a: HashMap<String, Vec<String>>,
    pub aaaa: HashMap<String, Vec<String>>,
    /// True → every lookup fails (simulates a resolver outage).
    pub fail_all: bool,
}

impl StubDns {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn txt(mut self, name: &str, values: &[&str]) -> Self {
        self.txt.insert(
            name.to_ascii_lowercase(),
            values.iter().map(|v| v.to_string()).collect(),
        );
        self
    }

    pub fn empty_txt(mut self, name: &str) -> Self {
        self.txt.insert(name.to_ascii_lowercase(), Vec::new());
        self
    }

    pub fn mx(mut self, name: &str, priority: u16, exchange: &str) -> Self {
        self.mx
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(MxRecord::new(priority, exchange));
        self
    }

    pub fn a(mut self, name: &str, ip: &str) -> Self {
        self.a
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(ip.to_string());
        self
    }

    pub fn aaaa(mut self, name: &str, ip: &str) -> Self {
        self.aaaa
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(ip.to_string());
        self
    }

    pub fn spf(mut self, name: &str, raw: &str) -> Self {
        self.spf
            .insert(name.to_ascii_lowercase(), SpfRecord::parse(raw));
        self
    }

    /// `name` is the DOMAIN the trait lookup receives.
    pub fn dmarc(mut self, name: &str, raw: &str) -> Self {
        self.dmarc
            .insert(name.to_ascii_lowercase(), DmarcPolicy::parse(raw));
        self
    }

    pub fn dkim(mut self, selector: &str, domain: &str, raw: &str) -> Self {
        self.dkim.insert(
            format!("{selector}._domainkey.{domain}").to_ascii_lowercase(),
            DkimRecord::parse(raw),
        );
        self
    }

    fn get_or_empty<T: Clone>(&self, map: &HashMap<String, T>, name: &str) -> Result<T, String> {
        if self.fail_all {
            return Err("resolver outage (stub)".to_string());
        }
        match map.get(&name.to_ascii_lowercase()) {
            Some(value) => Ok(value.clone()),
            None => Err("NXDOMAIN (stub)".to_string()),
        }
    }
}

impl DnsProvider for StubDns {
    fn lookup_txt<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>> {
        let result = self.get_or_empty(&self.txt, name);
        Box::pin(async move { result })
    }

    fn lookup_mx<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<MxRecord>> {
        let result = self.get_or_empty(&self.mx, name);
        Box::pin(async move { result })
    }

    fn lookup_spf<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Option<SpfRecord>> {
        let result = self.get_or_empty(&self.spf, name);
        Box::pin(async move { result })
    }

    fn lookup_dmarc<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Option<DmarcPolicy>> {
        // The trait contract is domain-in (the real resolver prepends
        // `_dmarc.` internally), so the stub keys records by bare domain too.
        let result = self.get_or_empty(&self.dmarc, name);
        Box::pin(async move { result })
    }

    fn lookup_dkim<'a>(
        &'a self,
        selector: &'a str,
        domain: &'a str,
    ) -> DnsFuture<'a, Option<DkimRecord>> {
        let name = format!("{selector}._domainkey.{domain}");
        let result = self.get_or_empty(&self.dkim, &name);
        Box::pin(async move { result })
    }

    fn lookup_a<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>> {
        let result = self.get_or_empty(&self.a, name);
        Box::pin(async move { result })
    }

    fn lookup_aaaa<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>> {
        let result = self.get_or_empty(&self.aaaa, name);
        Box::pin(async move { result })
    }
}
