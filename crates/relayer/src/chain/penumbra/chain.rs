use std::sync::Arc;

use ibc_relayer_types::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use ibc_relayer_types::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc_relayer_types::clients::ics07_tendermint::header::Header as TmHeader;
use penumbra_view::ViewService;
use tendermint::time::Time as TmTime;
use tendermint_light_client::verifier::types::LightBlock as TmLightBlock;
use tokio::runtime::Runtime as TokioRuntime;

use crate::{
    chain::{
        endpoint::{ChainEndpoint, HealthCheck},
        handle::Subscription,
    },
    config::{ChainConfig, Error as ConfigError},
    error::Error,
    keyring::Secp256k1KeyPair,
};

use super::config::PenumbraConfig;

pub struct PenumbraChain {
    config: PenumbraConfig,
    rt: Arc<TokioRuntime>,
    // TODO: need a handle for a view service, spawned on rt that we can use with rt.block_on
    // TODO: need a custody service
}

impl PenumbraChain {}

impl ChainEndpoint for PenumbraChain {
    type LightBlock = TmLightBlock;
    type Header = TmHeader;
    type ConsensusState = TmConsensusState;
    type ClientState = TmClientState;
    type Time = TmTime;
    // Note: this is a placeholder, we won't actually use it.
    type SigningKeyPair = Secp256k1KeyPair;

    fn id(&self) -> &ibc_relayer_types::core::ics24_host::identifier::ChainId {
        &self.config.id
    }

    fn config(&self) -> ChainConfig {
        ChainConfig::Penumbra(self.config.clone())
    }

    fn bootstrap(config: ChainConfig, rt: Arc<TokioRuntime>) -> Result<Self, Error> {
        let ChainConfig::Penumbra(config) = config else {
            return Err(Error::config(ConfigError::wrong_type()));
        };

        let fvk = config.kms_config.spend_key.full_viewing_key();

        // TODO: pass None until we figure out where to persist view data
        let view_service = rt
            .block_on(ViewService::load_or_initialize(
                None::<&str>,
                fvk,
                config.grpc_addr.clone().into(),
            ))
            .map_err(|e| Error::temp_penumbra_error(e.to_string()))?;

        tracing::info!("starting view service sync");

        // Wait for the view service to sync with the chain.
        let vs2 = view_service.clone();
        let sync_height = rt
            .block_on(async move {
                // TODO: ViewService should implement ViewClient on itself for local access
                let mut stream = vs2.status_stream().await?;
                let mut sync_height = 0u64;
                while let Some(status) = stream.next().await.transpose()? {
                    sync_height = status.full_sync_height;
                }
                Ok(sync_height)
            })
            .map_err(|e| Error::temp_penumbra_error(e.to_string()))?;

        tracing::info!(?sync_height, "view service sync complete");

        todo!()
    }

    fn shutdown(self) -> Result<(), Error> {
        todo!()
    }

    fn health_check(&mut self) -> Result<HealthCheck, Error> {
        todo!()
    }

    fn subscribe(&mut self) -> Result<Subscription, Error> {
        todo!()
    }

    fn keybase(&self) -> &crate::keyring::KeyRing<Self::SigningKeyPair> {
        todo!()
    }

    fn keybase_mut(&mut self) -> &mut crate::keyring::KeyRing<Self::SigningKeyPair> {
        todo!()
    }

    fn get_signer(&self) -> Result<ibc_relayer_types::signer::Signer, Error> {
        todo!()
    }

    fn get_key(&self) -> Result<Self::SigningKeyPair, Error> {
        todo!()
    }

    fn version_specs(&self) -> Result<crate::chain::cosmos::version::Specs, Error> {
        todo!()
    }

    fn send_messages_and_wait_commit(
        &mut self,
        tracked_msgs: crate::chain::tracking::TrackedMsgs,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, Error> {
        todo!()
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: crate::chain::tracking::TrackedMsgs,
    ) -> Result<Vec<tendermint_rpc::endpoint::broadcast::tx_sync::Response>, Error> {
        todo!()
    }

    fn verify_header(
        &mut self,
        trusted: ibc_relayer_types::Height,
        target: ibc_relayer_types::Height,
        client_state: &crate::client_state::AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        todo!()
    }

    fn check_misbehaviour(
        &mut self,
        update: &ibc_relayer_types::core::ics02_client::events::UpdateClient,
        client_state: &crate::client_state::AnyClientState,
    ) -> Result<Option<crate::misbehaviour::MisbehaviourEvidence>, Error> {
        todo!()
    }

    fn query_balance(
        &self,
        key_name: Option<&str>,
        denom: Option<&str>,
    ) -> Result<crate::account::Balance, Error> {
        todo!()
    }

    fn query_all_balances(
        &self,
        key_name: Option<&str>,
    ) -> Result<Vec<crate::account::Balance>, Error> {
        todo!()
    }

    fn query_denom_trace(&self, hash: String) -> Result<crate::denom::DenomTrace, Error> {
        todo!()
    }

    fn query_commitment_prefix(
        &self,
    ) -> Result<ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix, Error>
    {
        todo!()
    }

    fn query_application_status(&self) -> Result<crate::chain::endpoint::ChainStatus, Error> {
        todo!()
    }

    fn query_clients(
        &self,
        request: crate::chain::requests::QueryClientStatesRequest,
    ) -> Result<Vec<crate::client_state::IdentifiedAnyClientState>, Error> {
        todo!()
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
        Error,
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
        Error,
    > {
        todo!()
    }

    fn query_consensus_state_heights(
        &self,
        request: crate::chain::requests::QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ibc_relayer_types::Height>, Error> {
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
        Error,
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
        Error,
    > {
        todo!()
    }

    fn query_connections(
        &self,
        request: crate::chain::requests::QueryConnectionsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics03_connection::connection::IdentifiedConnectionEnd>,
        Error,
    > {
        todo!()
    }

    fn query_client_connections(
        &self,
        request: crate::chain::requests::QueryClientConnectionsRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics24_host::identifier::ConnectionId>, Error> {
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
        Error,
    > {
        todo!()
    }

    fn query_connection_channels(
        &self,
        request: crate::chain::requests::QueryConnectionChannelsRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::channel::IdentifiedChannelEnd>, Error>
    {
        todo!()
    }

    fn query_channels(
        &self,
        request: crate::chain::requests::QueryChannelsRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::channel::IdentifiedChannelEnd>, Error>
    {
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
        Error,
    > {
        todo!()
    }

    fn query_channel_client_state(
        &self,
        request: crate::chain::requests::QueryChannelClientStateRequest,
    ) -> Result<Option<crate::client_state::IdentifiedAnyClientState>, Error> {
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
        Error,
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
        Error,
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
        Error,
    > {
        todo!()
    }

    fn query_unreceived_packets(
        &self,
        request: crate::chain::requests::QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>, Error> {
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
        Error,
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
        Error,
    > {
        todo!()
    }

    fn query_unreceived_acknowledgements(
        &self,
        request: crate::chain::requests::QueryUnreceivedAcksRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>, Error> {
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
        Error,
    > {
        todo!()
    }

    fn query_txs(
        &self,
        request: crate::chain::requests::QueryTxRequest,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, Error> {
        todo!()
    }

    fn query_packet_events(
        &self,
        request: crate::chain::requests::QueryPacketEventDataRequest,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, Error> {
        todo!()
    }

    fn query_host_consensus_state(
        &self,
        request: crate::chain::requests::QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        todo!()
    }

    fn build_client_state(
        &self,
        height: ibc_relayer_types::Height,
        settings: crate::chain::client::ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        todo!()
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        todo!()
    }

    fn build_header(
        &mut self,
        trusted_height: ibc_relayer_types::Height,
        target_height: ibc_relayer_types::Height,
        client_state: &crate::client_state::AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        todo!()
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        channel_id: &ibc_relayer_types::core::ics24_host::identifier::ChannelId,
        port_id: &ibc_relayer_types::core::ics24_host::identifier::PortId,
        counterparty_payee: &ibc_relayer_types::signer::Signer,
    ) -> Result<(), Error> {
        todo!()
    }

    fn cross_chain_query(
        &self,
        requests: Vec<crate::chain::requests::CrossChainQueryRequest>,
    ) -> Result<
        Vec<ibc_relayer_types::applications::ics31_icq::response::CrossChainQueryResponse>,
        Error,
    > {
        todo!()
    }

    fn query_incentivized_packet(
        &self,
        request: ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketRequest,
    ) -> Result<ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketResponse, Error> {
        todo!()
    }

    fn query_consumer_chains(
        &self,
    ) -> Result<
        Vec<(
            ibc_relayer_types::core::ics24_host::identifier::ChainId,
            ibc_relayer_types::core::ics24_host::identifier::ClientId,
        )>,
        Error,
    > {
        todo!()
    }
}
