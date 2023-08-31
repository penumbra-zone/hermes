use std::{str::FromStr, sync::Arc};

use crate::chain::endpoint::{ChainEndpoint, HealthCheck};

use crate::client_state::IdentifiedAnyClientState;
use crate::config::ChainConfig;
use crate::error::Error;
use crate::keyring::Secp256k1KeyPair;
use crate::light_client::tendermint::LightClient as TmLightClient;
use crate::light_client::LightClient;
use crate::util::pretty::PrettyIdentifiedClientState;
use futures::Future;
use http::Uri;
use ibc_relayer_types::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use ibc_relayer_types::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc_relayer_types::clients::ics07_tendermint::header::Header as TmHeader;
use ibc_relayer_types::core::ics24_host::identifier::ClientId;
use tendermint::node::info::TxIndexStatus;
use tendermint::time::Time as TmTime;
use tendermint_light_client::verifier::types::LightBlock as TmLightBlock;
use tendermint_rpc::client::CompatMode;
use tendermint_rpc::endpoint::status;
use tendermint_rpc::{Client, HttpClient};
use tokio::runtime::Runtime as TokioRuntime;
use tracing::{error, info, instrument, trace, warn};

/// Returns the suffix counter for a CosmosSDK client id.
/// Returns `None` if the client identifier is malformed
/// and the suffix could not be parsed.
fn client_id_suffix(client_id: &ClientId) -> Option<u64> {
    client_id
        .as_str()
        .split('-')
        .last()
        .and_then(|e| e.parse::<u64>().ok())
}

pub struct PenumbraChain {
    config: ChainConfig,
    rpc_client: HttpClient,
    compat_mode: CompatMode,
    grpc_addr: Uri,
    light_client: TmLightClient,
    rt: Arc<TokioRuntime>,
}

impl ChainEndpoint for PenumbraChain {
    type LightBlock = TmLightBlock;
    type Header = TmHeader;
    type ConsensusState = TmConsensusState;
    type ClientState = TmClientState;
    type Time = TmTime;
    // TODO: don't do this
    type SigningKeyPair = Secp256k1KeyPair;

    fn config(&self) -> &crate::config::ChainConfig {
        &self.config
    }

    fn bootstrap(
        config: crate::config::ChainConfig,
        rt: std::sync::Arc<tokio::runtime::Runtime>,
    ) -> Result<Self, crate::error::Error> {
        let mut rpc_client = HttpClient::new(config.rpc_addr.clone())
            .map_err(|e| Error::rpc(config.rpc_addr.clone(), e))?;

        // The node info is the same for a Penumbra chain as a Cosmos-SDK chain.
        use crate::chain::cosmos::fetch_node_info;

        let node_info = rt.block_on(fetch_node_info(&rpc_client, &config))?;

        let compat_mode = CompatMode::from_version(node_info.version).unwrap_or_else(|e| {
            warn!("Unsupported tendermint version, will use v0.37 compatibility mode but relaying might not work as desired: {e}");
            CompatMode::V0_37
        });
        rpc_client.set_compat_mode(compat_mode);

        let light_client = TmLightClient::from_config(&config, node_info.id)?;

        let grpc_addr = Uri::from_str(&config.grpc_addr.to_string())
            .map_err(|e| Error::invalid_uri(config.grpc_addr.to_string(), e))?;

        let chain = Self {
            config,
            rpc_client,
            compat_mode,
            grpc_addr,
            light_client,
            rt,
        };

        Ok(chain)
    }

    fn shutdown(self) -> Result<(), crate::error::Error> {
        todo!()
    }

    fn health_check(&mut self) -> Result<crate::chain::endpoint::HealthCheck, crate::error::Error> {
        if let Err(e) = self.do_health_check() {
            warn!("Health checkup for chain '{}' failed", self.id());
            warn!("    Reason: {}", e.detail());
            warn!("    Some Hermes features may not work in this mode!");

            return Ok(HealthCheck::Unhealthy(Box::new(e)));
        }

        /*
        if let Err(e) = self.validate_params() {
            warn!("Hermes might be misconfigured for chain '{}'", self.id());
            warn!("    Reason: {}", e.detail());
            warn!("    Some Hermes features may not work in this mode!");

            return Ok(HealthCheck::Unhealthy(Box::new(e)));
        }
         */

        Ok(HealthCheck::Healthy)
    }

    fn subscribe(&mut self) -> Result<crate::chain::handle::Subscription, crate::error::Error> {
        todo!()
    }

    fn keybase(&self) -> &crate::keyring::KeyRing<Self::SigningKeyPair> {
        todo!()
    }

    fn keybase_mut(&mut self) -> &mut crate::keyring::KeyRing<Self::SigningKeyPair> {
        todo!()
    }

    fn get_signer(&self) -> Result<ibc_relayer_types::signer::Signer, crate::error::Error> {
        todo!()
    }

    fn ibc_version(&self) -> Result<Option<semver::Version>, crate::error::Error> {
        todo!()
    }

    fn send_messages_and_wait_commit(
        &mut self,
        tracked_msgs: crate::chain::tracking::TrackedMsgs,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, crate::error::Error> {
        todo!()
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: crate::chain::tracking::TrackedMsgs,
    ) -> Result<Vec<tendermint_rpc::endpoint::broadcast::tx_sync::Response>, crate::error::Error>
    {
        todo!()
    }

    fn verify_header(
        &mut self,
        trusted: ibc_relayer_types::Height,
        target: ibc_relayer_types::Height,
        client_state: &crate::client_state::AnyClientState,
    ) -> Result<Self::LightBlock, crate::error::Error> {
        crate::time!(
            "verify_header",
            {
                "src_chain": self.config().id.to_string(),
            }
        );

        let now = self.chain_status()?.sync_info.latest_block_time;

        self.light_client
            .verify(trusted, target, client_state, now)
            .map(|v| v.target)
    }

    fn check_misbehaviour(
        &mut self,
        update: &ibc_relayer_types::core::ics02_client::events::UpdateClient,
        client_state: &crate::client_state::AnyClientState,
    ) -> Result<Option<crate::misbehaviour::MisbehaviourEvidence>, crate::error::Error> {
        crate::time!(
            "check_misbehaviour",
            {
                "src_chain": self.config().id.to_string(),
            }
        );

        let now = self.chain_status()?.sync_info.latest_block_time;

        self.light_client
            .detect_misbehaviour(update, client_state, now)
    }

    fn query_balance(
        &self,
        key_name: Option<&str>,
        denom: Option<&str>,
    ) -> Result<crate::account::Balance, crate::error::Error> {
        todo!()
    }

    fn query_all_balances(
        &self,
        key_name: Option<&str>,
    ) -> Result<Vec<crate::account::Balance>, crate::error::Error> {
        todo!()
    }

    fn query_denom_trace(
        &self,
        hash: String,
    ) -> Result<crate::denom::DenomTrace, crate::error::Error> {
        todo!()
    }

    fn query_commitment_prefix(
        &self,
    ) -> Result<
        ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix,
        crate::error::Error,
    > {
        todo!()
    }

    fn query_application_status(
        &self,
    ) -> Result<crate::chain::endpoint::ChainStatus, crate::error::Error> {
        todo!()
    }

    fn query_clients(
        &self,
        request: crate::chain::requests::QueryClientStatesRequest,
    ) -> Result<Vec<crate::client_state::IdentifiedAnyClientState>, crate::error::Error> {
        crate::time!(
            "query_clients",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_clients");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::client::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());
        let response = self
            .block_on(client.client_states(request))
            .map_err(|e| Error::grpc_status(e, "query_clients".to_owned()))?
            .into_inner();

        // Deserialize into domain type
        let mut clients: Vec<IdentifiedAnyClientState> = response
            .client_states
            .into_iter()
            .filter_map(|cs| {
                IdentifiedAnyClientState::try_from(cs.clone())
                    .map_err(|e| {
                        warn!(
                            "failed to parse client state {}. Error: {}",
                            PrettyIdentifiedClientState(&cs),
                            e
                        )
                    })
                    .ok()
            })
            .collect();

        // Sort by client identifier counter
        clients.sort_by_cached_key(|c| client_id_suffix(&c.client_id).unwrap_or(0));

        Ok(clients)
    }

    fn query_client_state(
        &self,
        request: crate::chain::requests::QueryClientStateRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            crate::client_state::AnyClientState,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_consensus_state(
        &self,
        request: crate::chain::requests::QueryConsensusStateRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            crate::consensus_state::AnyConsensusState,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_consensus_state_heights(
        &self,
        request: crate::chain::requests::QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ibc_relayer_types::Height>, crate::error::Error> {
        todo!()
    }

    fn query_upgraded_client_state(
        &self,
        request: crate::chain::requests::QueryUpgradedClientStateRequest,
    ) -> Result<
        (
            crate::client_state::AnyClientState,
            ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_upgraded_consensus_state(
        &self,
        request: crate::chain::requests::QueryUpgradedConsensusStateRequest,
    ) -> Result<
        (
            crate::consensus_state::AnyConsensusState,
            ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_connections(
        &self,
        request: crate::chain::requests::QueryConnectionsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics03_connection::connection::IdentifiedConnectionEnd>,
        crate::error::Error,
    > {
        todo!()
    }

    fn query_client_connections(
        &self,
        request: crate::chain::requests::QueryClientConnectionsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics24_host::identifier::ConnectionId>,
        crate::error::Error,
    > {
        todo!()
    }

    fn query_connection(
        &self,
        request: crate::chain::requests::QueryConnectionRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            ibc_relayer_types::core::ics03_connection::connection::ConnectionEnd,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_connection_channels(
        &self,
        request: crate::chain::requests::QueryConnectionChannelsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics04_channel::channel::IdentifiedChannelEnd>,
        crate::error::Error,
    > {
        todo!()
    }

    fn query_channels(
        &self,
        request: crate::chain::requests::QueryChannelsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics04_channel::channel::IdentifiedChannelEnd>,
        crate::error::Error,
    > {
        todo!()
    }

    fn query_channel(
        &self,
        request: crate::chain::requests::QueryChannelRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            ibc_relayer_types::core::ics04_channel::channel::ChannelEnd,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_channel_client_state(
        &self,
        request: crate::chain::requests::QueryChannelClientStateRequest,
    ) -> Result<Option<crate::client_state::IdentifiedAnyClientState>, crate::error::Error> {
        todo!()
    }

    fn query_packet_commitment(
        &self,
        request: crate::chain::requests::QueryPacketCommitmentRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            Vec<u8>,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_packet_commitments(
        &self,
        request: crate::chain::requests::QueryPacketCommitmentsRequest,
    ) -> Result<
        (
            Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>,
            ibc_relayer_types::Height,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_packet_receipt(
        &self,
        request: crate::chain::requests::QueryPacketReceiptRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            Vec<u8>,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_unreceived_packets(
        &self,
        request: crate::chain::requests::QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>, crate::error::Error>
    {
        todo!()
    }

    fn query_packet_acknowledgement(
        &self,
        request: crate::chain::requests::QueryPacketAcknowledgementRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            Vec<u8>,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_packet_acknowledgements(
        &self,
        request: crate::chain::requests::QueryPacketAcknowledgementsRequest,
    ) -> Result<
        (
            Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>,
            ibc_relayer_types::Height,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_unreceived_acknowledgements(
        &self,
        request: crate::chain::requests::QueryUnreceivedAcksRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>, crate::error::Error>
    {
        todo!()
    }

    fn query_next_sequence_receive(
        &self,
        request: crate::chain::requests::QueryNextSequenceReceiveRequest,
        include_proof: crate::chain::requests::IncludeProof,
    ) -> Result<
        (
            ibc_relayer_types::core::ics04_channel::packet::Sequence,
            Option<ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof>,
        ),
        crate::error::Error,
    > {
        todo!()
    }

    fn query_txs(
        &self,
        request: crate::chain::requests::QueryTxRequest,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, crate::error::Error> {
        todo!()
    }

    fn query_packet_events(
        &self,
        request: crate::chain::requests::QueryPacketEventDataRequest,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, crate::error::Error> {
        todo!()
    }

    fn query_host_consensus_state(
        &self,
        request: crate::chain::requests::QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, crate::error::Error> {
        todo!()
    }

    fn build_client_state(
        &self,
        height: ibc_relayer_types::Height,
        settings: crate::chain::client::ClientSettings,
    ) -> Result<Self::ClientState, crate::error::Error> {
        todo!()
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, crate::error::Error> {
        todo!()
    }

    fn build_header(
        &mut self,
        trusted_height: ibc_relayer_types::Height,
        target_height: ibc_relayer_types::Height,
        client_state: &crate::client_state::AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), crate::error::Error> {
        todo!()
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        channel_id: &ibc_relayer_types::core::ics24_host::identifier::ChannelId,
        port_id: &ibc_relayer_types::core::ics24_host::identifier::PortId,
        counterparty_payee: &ibc_relayer_types::signer::Signer,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    fn cross_chain_query(
        &self,
        requests: Vec<crate::chain::requests::CrossChainQueryRequest>,
    ) -> Result<
        Vec<ibc_relayer_types::applications::ics31_icq::response::CrossChainQueryResponse>,
        crate::error::Error,
    > {
        todo!()
    }

    fn query_incentivized_packet(
        &self,
        request: ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketRequest,
    ) -> Result<ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketResponse, crate::error::Error>
    {
        todo!()
    }
}

impl PenumbraChain {
    /// Run a future to completion on the Tokio runtime.
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    /// Query the chain status via an RPC query.
    ///
    /// Returns an error if the node is still syncing and has not caught up,
    /// ie. if `sync_info.catching_up` is `true`.
    fn chain_status(&self) -> Result<status::Response, Error> {
        crate::time!(
            "chain_status",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "status");

        let status = self
            .block_on(self.rpc_client.status())
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        if status.sync_info.catching_up {
            return Err(Error::chain_not_caught_up(
                self.config.rpc_addr.to_string(),
                self.config().id.clone(),
            ));
        }

        Ok(status)
    }

    /// Performs a health check on a Penumbra chain.
    ///
    /// This health check checks on the following in this order:
    /// 1. Checks on the self-reported health endpoint.
    /// 2. Checks that transaction indexing is enabled.
    /// 3. Checks that the self-reported chain ID matches the configured one.
    fn do_health_check(&self) -> Result<(), Error> {
        let chain_id = self.id();
        let grpc_address = self.grpc_addr.to_string();
        let rpc_address = self.config.rpc_addr.to_string();

        self.block_on(self.rpc_client.health()).map_err(|e| {
            Error::health_check_json_rpc(
                chain_id.clone(),
                rpc_address.clone(),
                "/health".to_string(),
                e,
            )
        })?;

        let status = self.chain_status()?;

        if status.node_info.other.tx_index != TxIndexStatus::On {
            return Err(Error::tx_indexing_disabled(chain_id.clone()));
        }

        if status.node_info.network.as_str() != chain_id.as_str() {
            // Log the error, continue optimistically
            error!(
                "/status endpoint from chain '{}' reports network identifier to be '{}'. \
            This is usually a sign of misconfiguration, please check your config.toml",
                chain_id, status.node_info.network
            );
        }

        Ok(())
    }
}
