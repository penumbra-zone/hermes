use core::time::Duration;

use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use penumbra_custody::soft_kms;
use serde_derive::{Deserialize, Serialize};
use tendermint_rpc::Url;

use crate::config::{default, EventSourceMode, PacketFilter, RefreshRate};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PenumbraConfig {
    pub id: ChainId,
    /// The URL of the app's gRPC endpoint.
    pub grpc_addr: Url,
    /// The URL of the cometbft RPC endpoint.
    ///
    /// TODO: in the long term, it would be desirable to eliminate this entirely.
    pub rpc_addr: Url,

    /// The type of event source and associated settings
    pub event_source: EventSourceMode,

    /// Timeout used when issuing RPC queries
    #[serde(default = "default::rpc_timeout", with = "humantime_serde")]
    pub rpc_timeout: Duration,

    /// Controls which packets will be relayed.
    #[serde(default)]
    pub packet_filter: PacketFilter,
    pub clear_interval: Option<u64>,
    /// How many packets to fetch at once from the chain when clearing packets
    #[serde(default = "default::query_packets_chunk_size")]
    pub query_packets_chunk_size: usize,
    #[serde(default = "default::max_block_time", with = "humantime_serde")]
    pub max_block_time: Duration,

    /// The rate at which to refresh the client referencing this chain,
    /// expressed as a fraction of the trusting period.
    #[serde(default = "default::client_refresh_rate")]
    pub client_refresh_rate: RefreshRate,

    /// Key configuration
    ///
    /// This is used instead of the Hermes keyring, which doesn't yet handle
    /// Penumbra-specific key concerns. In the future, we may want to merge
    /// this with the Hermes keyring, but it's a low-priority item.
    pub kms_config: soft_kms::Config,

    /// A fake key name, not used except to satisfy external interfaces.
    ///
    /// The Config::key_name() method returns &String, forcing configs to own a String.
    /// We don't want to just change the method, because we want our fork to apply cleanly
    /// onto upstream, so we need to
    /// 1. use a stub field (here)
    /// 2. create a separate PR to change the method signature
    /// 3. rebase our change stack once it's merged and remove the stub field.
    #[serde(default)]
    pub stub_key_name: String,
}
