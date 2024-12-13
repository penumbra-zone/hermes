//! Custom `serde` deserializer for `FilterMatch`

use core::{fmt, str::FromStr};
use std::{collections::HashMap, hash::Hash};

use ibc_relayer_types::{
    applications::transfer::RawCoin,
    bigint::U256,
    core::ics24_host::identifier::{ChannelId, ClientId, PortId},
    events::IbcEventType,
};
use itertools::Itertools;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Represents all the filtering policies for packets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketFilter {
    #[serde(flatten)]
    pub channel_policy: ChannelPolicy,
    #[serde(default)]
    pub min_fees: HashMap<ChannelFilterMatch, FeePolicy>,
}

impl Default for PacketFilter {
    /// By default, allows all channels & ports.
    fn default() -> Self {
        Self {
            channel_policy: ChannelPolicy::default(),
            min_fees: HashMap::new(),
        }
    }
}

impl PacketFilter {
    pub fn new(
        channel_policy: ChannelPolicy,
        min_fees: HashMap<ChannelFilterMatch, FeePolicy>,
    ) -> Self {
        Self {
            channel_policy,
            min_fees,
        }
    }

    pub fn allow(channel_filters: Vec<(PortFilterMatch, ChannelFilterMatch)>) -> PacketFilter {
        PacketFilter::new(
            ChannelPolicy::Allow(ChannelFilters::new(channel_filters)),
            HashMap::new(),
        )
    }
}

/// Represents all the filtering policies for clients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientFilter {
    #[serde(flatten)]
    pub client_policy: ClientPolicy,
}

impl Default for ClientFilter {
    /// By default, allows all clients.
    fn default() -> Self {
        Self {
            client_policy: ClientPolicy::default(),
        }
    }
}

impl ClientFilter {
    pub fn new(client_policy: ClientPolicy) -> Self {
        Self { client_policy }
    }

    pub fn allow(client_filters: Vec<ClientFilterMatch>) -> ClientFilter {
        ClientFilter::new(ClientPolicy::Allow(ClientFilters::new(client_filters)))
    }
}

/// Represents the ways in which packets can be filtered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "lowercase",
    tag = "policy",
    content = "list",
    deny_unknown_fields
)]
pub enum ChannelPolicy {
    /// Allow packets from the specified channels.
    Allow(ChannelFilters),
    /// Deny packets from the specified channels.
    Deny(ChannelFilters),
    /// Allow any & all packets.
    AllowAll,
}

/// Represents the policy used to filter incentivized packets.
/// Currently only filtering on `recv_fee` is authorized.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    recv: Vec<MinFee>,
}

impl FeePolicy {
    pub fn new(recv: Vec<MinFee>) -> Self {
        Self { recv }
    }

    pub fn should_relay(&self, event_type: IbcEventType, fees: &[RawCoin]) -> bool {
        match event_type {
            IbcEventType::SendPacket => fees
                .iter()
                .any(|fee| self.recv.iter().any(|e| e.is_enough(fee))),
            _ => true,
        }
    }
}

/// Represents the minimum fee authorized when filtering.
/// If no denom is specified, any denom is allowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinFee {
    amount: u64,
    denom: Option<String>,
}

impl MinFee {
    pub fn new(amount: u64, denom: Option<String>) -> Self {
        Self { amount, denom }
    }

    pub fn is_enough(&self, fee: &RawCoin) -> bool {
        match self.denom.clone() {
            Some(denom) => fee.amount.0 >= U256::from(self.amount) && denom.eq(&fee.denom),
            None => fee.amount.0 >= U256::from(self.amount),
        }
    }
}

impl Default for ChannelPolicy {
    /// By default, allows all channels & ports.
    fn default() -> Self {
        Self::AllowAll
    }
}

impl ChannelPolicy {
    /// Returns true if the packets can be relayed on the channel with [`PortId`] and [`ChannelId`],
    /// false otherwise.
    pub fn is_allowed(&self, port_id: &PortId, channel_id: &ChannelId) -> bool {
        match self {
            ChannelPolicy::Allow(filters) => filters.matches((port_id, channel_id)),
            ChannelPolicy::Deny(filters) => !filters.matches((port_id, channel_id)),
            ChannelPolicy::AllowAll => true,
        }
    }
}

/// The internal representation of channel filter policies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelFilters(Vec<(PortFilterMatch, ChannelFilterMatch)>);

impl ChannelFilters {
    /// Create a new filter from the given list of port/channel filters.
    pub fn new(filters: Vec<(PortFilterMatch, ChannelFilterMatch)>) -> Self {
        Self(filters)
    }

    /// Returns the number of filters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if there are no filters, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Indicates whether a match for the given [`PortId`]-[`ChannelId`] pair
    /// exists in the filter policy.
    pub fn matches(&self, channel_port: (&PortId, &ChannelId)) -> bool {
        let (port_id, channel_id) = channel_port;
        self.0.iter().any(|(port_filter, chan_filter)| {
            port_filter.matches(port_id) && chan_filter.matches(channel_id)
        })
    }

    /// Indicates whether this filter policy contains only exact patterns.
    #[inline]
    pub fn is_exact(&self) -> bool {
        self.0.iter().all(|(port_filter, channel_filter)| {
            port_filter.is_exact() && channel_filter.is_exact()
        })
    }

    /// An iterator over the [`PortId`]-[`ChannelId`] pairs that don't contain wildcards.
    pub fn iter_exact(&self) -> impl Iterator<Item = (&PortId, &ChannelId)> {
        self.0.iter().filter_map(|port_chan_filter| {
            if let &(FilterPattern::Exact(ref port_id), FilterPattern::Exact(ref chan_id)) =
                port_chan_filter
            {
                Some((port_id, chan_id))
            } else {
                None
            }
        })
    }
}

impl fmt::Display for ChannelFilters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|(pid, cid)| format!("{pid}/{cid}"))
                .join(", ")
        )
    }
}

impl Serialize for ChannelFilters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        struct Pair<'a> {
            a: &'a FilterPattern<PortId>,
            b: &'a FilterPattern<ChannelId>,
        }

        impl<'a> Serialize for Pair<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(self.a)?;
                seq.serialize_element(self.b)?;
                seq.end()
            }
        }

        let mut outer_seq = serializer.serialize_seq(Some(self.0.len()))?;

        for (port, channel) in &self.0 {
            outer_seq.serialize_element(&Pair {
                a: port,
                b: channel,
            })?;
        }

        outer_seq.end()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientFilters(Vec<ClientFilterMatch>);

impl ClientFilters {
    /// Create a new filter from the given list of client filters.
    pub fn new(filters: Vec<ClientFilterMatch>) -> Self {
        Self(filters)
    }

    /// Returns the number of filters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if there are no filters, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Indicates whether a match for the given [`ClientId`]
    /// exists in the filter policy.
    pub fn matches(&self, client: &ClientId) -> bool {
        self.0
            .iter()
            .any(|client_filter| client_filter.matches(client))
    }

    /// Indicates whether this filter policy contains only exact patterns.
    #[inline]
    pub fn is_exact(&self) -> bool {
        self.0.iter().all(|client_filter| client_filter.is_exact())
    }

    /// An iterator over the [`ClientId`]s that don't contain wildcards.
    pub fn iter_exact(&self) -> impl Iterator<Item = &ClientId> {
        self.0.iter().filter_map(|client_filter| {
            if let FilterPattern::Exact(ref client_id) = client_filter {
                Some(client_id)
            } else {
                None
            }
        })
    }
}

impl fmt::Display for ClientFilters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|client_id| format!("{client_id}"))
                .join(", ")
        )
    }
}

impl Serialize for ClientFilters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        struct Item<'a> {
            a: &'a FilterPattern<ClientId>,
        }

        impl<'a> Serialize for Item<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(1))?;
                seq.serialize_element(self.a)?;
                seq.end()
            }
        }

        let mut outer_seq = serializer.serialize_seq(Some(self.0.len()))?;

        for client in &self.0 {
            outer_seq.serialize_element(&Item { a: client })?;
        }

        outer_seq.end()
    }
}

/// Represents the ways in which clients can be filtered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "lowercase",
    tag = "policy",
    content = "list",
    deny_unknown_fields
)]
pub enum ClientPolicy {
    /// Only scan the specified clients.
    Allow(ClientFilters),
    /// Scan all available clients.
    AllowAll,
}

impl Default for ClientPolicy {
    /// By default, allows all clients.
    fn default() -> Self {
        Self::AllowAll
    }
}

/// Newtype wrapper for expressing wildcard patterns compiled to a [`regex::Regex`].
#[derive(Clone, Debug)]
pub struct Wildcard {
    pattern: String,
    regex: regex::Regex,
}

impl Wildcard {
    pub fn new(pattern: String) -> Result<Self, regex::Error> {
        let escaped = regex::escape(&pattern).replace("\\*", "(?:.*)");
        let regex = format!("^{escaped}$").parse()?;
        Ok(Self { pattern, regex })
    }

    #[inline]
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

impl FromStr for Wildcard {
    type Err = regex::Error;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        Self::new(pattern.to_string())
    }
}

impl fmt::Display for Wildcard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pattern)
    }
}

impl Serialize for Wildcard {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.pattern)
    }
}

impl PartialEq for Wildcard {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for Wildcard {}

impl Hash for Wildcard {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
    }
}

/// Represents either a single channel to be filtered in a [`ChannelFilters`] list or
/// a single client to be filtered in a [`ClientFilters`] list.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum FilterPattern<T> {
    /// A channel specified exactly with its [`PortId`] & [`ChannelId`] or a client with its [`ClientId`].
    Exact(T),
    /// A glob of channel(s) specified with a wildcard in either or both [`PortId`] & [`ChannelId`], or a wildcard channel.
    Wildcard(Wildcard),
}

impl<T> FilterPattern<T> {
    /// Indicates whether this filter is specified in part with a wildcard.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard(_))
    }

    /// Indicates whether this filter is specified as an exact match.
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Matches the given value via strict equality if the filter is an `Exact`, or via
    /// wildcard matching if the filter is a `Pattern`.
    pub fn matches(&self, value: &T) -> bool
    where
        T: PartialEq + ToString,
    {
        match self {
            FilterPattern::Exact(v) => value == v,
            FilterPattern::Wildcard(regex) => regex.is_match(&value.to_string()),
        }
    }

    /// Returns the contained value if this filter contains an `Exact` variant, or
    /// `None` if it contains a `Pattern`.
    pub fn exact_value(&self) -> Option<&T> {
        match self {
            FilterPattern::Exact(value) => Some(value),
            FilterPattern::Wildcard(_) => None,
        }
    }
}

impl<T: fmt::Display> fmt::Display for FilterPattern<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterPattern::Exact(value) => write!(f, "{value}"),
            FilterPattern::Wildcard(regex) => write!(f, "{regex}"),
        }
    }
}

impl<T> Serialize for FilterPattern<T>
where
    T: ToString,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FilterPattern::Exact(e) => serializer.serialize_str(&e.to_string()),
            FilterPattern::Wildcard(t) => serializer.serialize_str(&t.to_string()),
        }
    }
}

/// Type alias for a [`FilterPattern`] containing a [`PortId`].
pub type PortFilterMatch = FilterPattern<PortId>;
/// Type alias for a [`FilterPattern`] containing a [`ChannelId`].
pub type ChannelFilterMatch = FilterPattern<ChannelId>;
/// Type alias for a [`FilterPattern`] containing a [`ClientId`].
pub type ClientFilterMatch = FilterPattern<ClientId>;

impl<'de> Deserialize<'de> for PortFilterMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<PortFilterMatch, D::Error> {
        deserializer.deserialize_string(port::PortFilterMatchVisitor)
    }
}

impl<'de> Deserialize<'de> for ChannelFilterMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ChannelFilterMatch, D::Error> {
        deserializer.deserialize_string(channel::ChannelFilterMatchVisitor)
    }
}

impl<'de> Deserialize<'de> for ClientFilterMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ClientFilterMatch, D::Error> {
        deserializer.deserialize_string(client::ClientFilterMatchVisitor)
    }
}

pub(crate) mod port {
    use super::*;

    pub struct PortFilterMatchVisitor;

    impl<'de> de::Visitor<'de> for PortFilterMatchVisitor {
        type Value = PortFilterMatch;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("valid PortId or wildcard")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            if let Ok(port_id) = PortId::from_str(v) {
                Ok(PortFilterMatch::Exact(port_id))
            } else {
                let wildcard = v.parse().map_err(E::custom)?;
                Ok(PortFilterMatch::Wildcard(wildcard))
            }
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }
    }
}

pub(crate) mod client {
    use super::*;

    pub struct ClientFilterMatchVisitor;

    impl<'de> de::Visitor<'de> for ClientFilterMatchVisitor {
        type Value = ClientFilterMatch;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("valid ClientId or wildcard")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            tracing::info!("ClientFilterMatchVisitor: visit_str: {}", v);
            if let Ok(client_id) = ClientId::from_str(v) {
                Ok(ClientFilterMatch::Exact(client_id))
            } else {
                let wildcard = v.parse().map_err(E::custom)?;
                Ok(ClientFilterMatch::Wildcard(wildcard))
            }
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }
    }
}
pub(crate) mod channel {
    use super::*;

    pub struct ChannelFilterMatchVisitor;

    impl<'de> de::Visitor<'de> for ChannelFilterMatchVisitor {
        type Value = ChannelFilterMatch;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("valid ChannelId or wildcard")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            if let Ok(channel_id) = ChannelId::from_str(v) {
                Ok(ChannelFilterMatch::Exact(channel_id))
            } else {
                let wildcard = v.parse().map_err(E::custom)?;
                Ok(ChannelFilterMatch::Wildcard(wildcard))
            }
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_packet_filter_policy() {
        let toml_content = r#"
            policy = 'allow'
            list = [
              ['ica*', '*'],
              ['transfer', 'channel-0'],
            ]
            "#;

        let filter_policy: ChannelPolicy =
            toml::from_str(toml_content).expect("could not parse filter policy");

        dbg!(filter_policy);
    }

    #[test]
    fn serialize_packet_filter_policy() {
        use std::str::FromStr;

        use ibc_relayer_types::core::ics24_host::identifier::{ChannelId, PortId};

        let filter_policy = ChannelFilters(vec![
            (
                FilterPattern::Exact(PortId::from_str("transfer").unwrap()),
                FilterPattern::Exact(ChannelId::from_str("channel-0").unwrap()),
            ),
            (
                FilterPattern::Wildcard("ica*".parse().unwrap()),
                FilterPattern::Wildcard("*".parse().unwrap()),
            ),
        ]);

        let fp = ChannelPolicy::Allow(filter_policy);
        let toml_str = toml::to_string_pretty(&fp).expect("could not serialize packet filter");

        println!("{toml_str}");
    }

    #[test]
    fn channel_filter_iter_exact() {
        let toml_content = r#"
            policy = 'deny'
            list = [
              ['ica', 'channel-*'],
              ['ica*', '*'],
              ['transfer', 'channel-0'],
              ['transfer*', 'channel-1'],
              ['ft-transfer', 'channel-2'],
            ]
            "#;

        let pf: ChannelPolicy =
            toml::from_str(toml_content).expect("could not parse filter policy");

        if let ChannelPolicy::Deny(channel_filters) = pf {
            let exact_matches = channel_filters.iter_exact().collect::<Vec<_>>();
            assert_eq!(
                exact_matches,
                vec![
                    (
                        &PortId::from_str("transfer").unwrap(),
                        &ChannelId::from_str("channel-0").unwrap()
                    ),
                    (
                        &PortId::from_str("ft-transfer").unwrap(),
                        &ChannelId::from_str("channel-2").unwrap()
                    )
                ]
            );
        } else {
            panic!("expected `ChannelPolicy::Deny` variant");
        }
    }

    #[test]
    fn packet_filter_deny_policy() {
        let deny_policy = r#"
            policy = 'deny'
            list = [
              ['ica', 'channel-*'],
              ['ica*', '*'],
              ['transfer', 'channel-0'],
              ['transfer*', 'channel-1'],
              ['ft-transfer', 'channel-2'],
            ]
            "#;

        let pf: ChannelPolicy = toml::from_str(deny_policy).expect("could not parse filter policy");

        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("transfer").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("ica-1").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
    }

    #[test]
    fn packet_filter_allow_policy() {
        let allow_policy = r#"
            policy = 'allow'
            list = [
              ['ica', 'channel-*'],
              ['ica*', '*'],
              ['transfer', 'channel-0'],
              ['transfer*', 'channel-1'],
              ['ft-transfer', 'channel-2'],
            ]
            "#;

        let pf: ChannelPolicy =
            toml::from_str(allow_policy).expect("could not parse filter policy");

        assert!(pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("transfer-1").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("ica-1").unwrap(),
            &ChannelId::from_str("channel-2").unwrap()
        ));
        assert!(pf.is_allowed(
            &PortId::from_str("ica").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
    }

    #[test]
    fn packet_filter_regex() {
        let allow_policy = r#"
            policy = 'allow'
            list = [
              ['transfer*', 'channel-1'],
            ]
            "#;

        let pf: ChannelPolicy =
            toml::from_str(allow_policy).expect("could not parse filter policy");

        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
        assert!(!pf.is_allowed(
            &PortId::from_str("ft-transfer-port").unwrap(),
            &ChannelId::from_str("channel-1").unwrap()
        ));
    }

    #[test]
    fn to_string_wildcards() {
        let wildcard = "ica*".parse::<Wildcard>().unwrap();
        assert_eq!(wildcard.to_string(), "ica*".to_string());
    }
}
