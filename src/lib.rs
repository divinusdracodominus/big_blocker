#![allow(non_snake_case)]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate err_derive;

use serde::{
    de::{self, Deserialize, Deserializer, Visitor},
    ser::{Serialize, Serializer},
};

use std::fmt;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Error)]
#[error(display = "blocker error")]
pub enum BlockError {
    #[error(display = "failed to execute command")]
    CommandFailed((String, i32)),
    #[error(display = "json parsing error")]
    JsonError(#[source] serde_json::error::Error),
    #[error(display = "{}", _0)]
    IOError(#[source] std::io::Error),
    #[error(display = "unexpected none value")]
    NoneError,
    #[error(display = "failed to parse address: {}", _0)]
    AddrParse(#[source] AddrParseError),
    #[error(display = "neither an ipv6 nor ipv4 prefix exists")]
    MissingPrefix,
    #[error(display = "{}", _0)]
    Utf8Error(#[source] std::string::FromUtf8Error),
    #[error(display = "{}", _0)]
    ParseIntError(#[source] std::num::ParseIntError),
}

/*impl From<std::option::NoneError> for BlockError {
    fn from(_: std::option::NoneError) -> Self {
        Self::NoneError
    }
}*/

pub trait Range {
    type Err: std::error::Error;
    fn prefix_count(&self) -> usize;
    fn prefixes(self) -> Result<Vec<IpPrefix>, Self::Err>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AWSRange {
    syncToken: String,
    createDate: String,
    prefixes: Vec<AmazonIp>,
}

impl Range for AWSRange {
    type Err = BlockError;
    fn prefix_count(&self) -> usize {
        self.prefixes.len()
    }
    fn prefixes(self) -> Result<Vec<IpPrefix>, Self::Err> {
        let mut outvec = Vec::with_capacity(self.prefixes.len());
        for p in self.prefixes.into_iter() {
            outvec.push(p.try_to_prefix()?);
        }
        Ok(outvec)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AmazonIp {
    ip_prefix: Option<V4Prefix>,
    ipv6_prefix: Option<V6Prefix>,
    region: String,
    service: String,
    network_border_group: String,
}

impl AmazonIp {
    pub fn try_to_prefix(self) -> Result<IpPrefix, BlockError> {
        if let Some(prefix) = self.ip_prefix {
            Ok(IpPrefix::V4(prefix))
        } else if let Some(prefix_6) = self.ipv6_prefix {
            Ok(IpPrefix::V6(prefix_6))
        } else {
            Err(BlockError::MissingPrefix)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleRange {
    syncToken: String,
    creationTime: String,
    prefixes: Vec<GoogleIp>,
}

impl Range for GoogleRange {
    type Err = BlockError;
    fn prefix_count(&self) -> usize {
        self.prefixes.len()
    }
    fn prefixes(self) -> Result<Vec<IpPrefix>, Self::Err> {
        let mut outvec = Vec::with_capacity(self.prefixes.len());
        for p in self.prefixes.into_iter() {
            outvec.push(p.try_to_prefix()?);
        }
        Ok(outvec)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleIp {
    ipv4Prefix: Option<V4Prefix>,
    ipv6Prefix: Option<V6Prefix>,
    service: Option<String>,
    scope: Option<String>,
}

impl GoogleIp {
    pub fn try_to_prefix(self) -> Result<IpPrefix, BlockError> {
        if let Some(prefix) = self.ipv4Prefix {
            Ok(IpPrefix::V4(prefix))
        } else if let Some(prefix_6) = self.ipv6Prefix {
            Ok(IpPrefix::V6(prefix_6))
        } else {
            Err(BlockError::MissingPrefix)
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct V4Prefix {
    ip: [u8; 4],
    prefix: u8,
}

impl FromStr for V4Prefix {
    type Err = BlockError;
    fn from_str(s: &str) -> Result<V4Prefix, BlockError> {
        let parts: Vec<&str> = s.split('/').collect();
        let ip: [u8; 4] = Ipv4Addr::from_str(match parts.get(0) {
            Some(value) => value,
            None => return Err(BlockError::NoneError),
        })?.octets();
        
        let prefix = match parts.get(1) {
            Some(value) => value,
            None => return Err(BlockError::NoneError),
        }.parse::<u8>()?;
        //print!("prefix: {} ", prefix);
        Ok(Self { ip, prefix })
    }
}

impl fmt::Display for V4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}/{}",
            self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.prefix
        )
    }
}

impl Serialize for V4Prefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

struct V4Visitor;
impl<'de> Visitor<'de> for V4Visitor {
    type Value = V4Prefix;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an string in the form 127.0.0.1/24")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<V4Prefix, E> {
        match V4Prefix::from_str(s) {
            Ok(pre) => Ok(pre),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<V4Prefix, E> {
        match V4Prefix::from_str(&s) {
            Ok(pre) => Ok(pre),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
}
impl<'de> Deserialize<'de> for V4Prefix {
    fn deserialize<D>(deserializer: D) -> Result<V4Prefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(V4Visitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6Prefix {
    ip: [u16; 8],
    prefix: u8,
}

impl FromStr for V6Prefix {
    type Err = BlockError;
    fn from_str(s: &str) -> Result<V6Prefix, BlockError> {
        let parts: Vec<&str> = s.split('/').collect();
        let ip: [u16; 8] = Ipv6Addr::from_str(match parts.get(0) {
            Some(value) => value,
            None => return Err(BlockError::NoneError),
        })?.segments();
        let prefix = match parts.get(1) {
            Some(value) => value,
            None => return Err(BlockError::NoneError),
        }.parse::<u8>()?;
        Ok(Self { ip, prefix })
    }
}

impl fmt::Display for V6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            Ipv6Addr::new(
                self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.ip[4], self.ip[5], self.ip[6],
                self.ip[7]
            ),
            self.prefix
        )
    }
}

impl Serialize for V6Prefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

struct V6Visitor;
impl<'de> Visitor<'de> for V6Visitor {
    type Value = V6Prefix;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an string in the form ffff:ffff:ffff::/60")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<V6Prefix, E> {
        match V6Prefix::from_str(s) {
            Ok(pre) => Ok(pre),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<V6Prefix, E> {
        match V6Prefix::from_str(&s) {
            Ok(pre) => Ok(pre),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
}
impl<'de> Deserialize<'de> for V6Prefix {
    fn deserialize<D>(deserializer: D) -> Result<V6Prefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(V6Visitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpPrefix {
    V4(V4Prefix),
    V6(V6Prefix),
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let display = match self {
            IpPrefix::V4(v4) => format!("{}", v4),
            IpPrefix::V6(v6) => format!("{}", v6),
        };
        write!(f, "{}", display)
    }
}

#[derive(Debug, Clone)]
pub struct Blocker {
    ips: Vec<IpPrefix>,
    save: bool,
}

impl Blocker {
    /// note save may become a unix only option with windows defaulting to true
    pub fn new(ips: Vec<IpPrefix>, save: bool) -> Self {
        Self { ips, save }
    }
    /// this will handle actually blocking ip addresses
    pub async fn block(&self) -> Result<(), BlockError> {
        for ip in self.ips.iter() {
            if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
                // replace OUTPUT with FORWARD if blocking NAT
                let output = tokio::process::Command::new("iptables")
                    .args(&["-A", "OUTPUT", "-d", &format!("{}", ip), "-j", "DROP"])
                    .output()
                    .await?;
                if !output.status.success() {
                    let code = output.status.code().unwrap();
                    let stderr = String::from_utf8(output.stderr)?;
                    return Err(BlockError::CommandFailed((stderr, code)));
                }
            }
            if cfg!(target_os = "windows") {
                let output = tokio::process::Command::new("netsh").args(&[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=\"BigBlocker\"",
                    "dir=out",
                    "action=deny",
                    "enable=yes",
                    &format!("remoteip={}", ip),
                    "profile=public"
                ]).output().await?;
                if !output.status.success() {
                    let code = output.status.code().unwrap();
                    let stdout = String::from_utf8(output.stdout)?;
                    return Err(BlockError::CommandFailed((stdout, code)));
                }
            }
        }
        Ok(())
    }
    /// resets firewall rules
    pub async fn unblock_all() -> Result<(), BlockError>{
        if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            let output = tokio::process::Command::new("iptables")
                .args(&["-F", "OUTPUT"])
                .output()
                .await?;
            if !output.status.success() {
                let code = output.status.code().unwrap();
                let stderr = String::from_utf8(output.stderr)?;
                return Err(BlockError::CommandFailed((stderr, code)));
            }
        }
        if cfg!(target_os = "windows") {
            let output = tokio::process::Command::new("netsh")
                .args(&["advfirewall", "reset"])
                .output()
                .await?;
            if !output.status.success() {
                let code = output.status.code().unwrap();
                let stdout = String::from_utf8(output.stdout)?;
                return Err(BlockError::CommandFailed((stdout, code)));
            }
        }
        Ok(())
    }
}