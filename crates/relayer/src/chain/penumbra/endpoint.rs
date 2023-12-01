use bytes::{Buf, Bytes};
use ibc_relayer_types::signer::Signer;
use std::thread;
use std::time::Duration;
use std::{str::FromStr, sync::Arc};

use crate::chain::client::ClientSettings;
use crate::chain::cosmos::query::status::query_status;
use crate::chain::cosmos::query::tx::{
    query_packets_from_block, query_packets_from_txs, query_txs,
};
use crate::chain::cosmos::query::QueryResponse;
use crate::chain::cosmos::sort_events_by_sequence;
use crate::chain::endpoint::{ChainEndpoint, ChainStatus, HealthCheck};
use crate::chain::penumbra::query::abci_query;
use crate::event::source::{EventSource, TxEventSourceCmd};

use crate::chain::requests::{IncludeProof, Qualified, QueryConnectionsRequest, QueryHeight};
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::ChainConfig;
use crate::consensus_state::AnyConsensusState;
use crate::error::Error;
use crate::keyring::{KeyRing, Secp256k1KeyPair, Store};
use crate::light_client::tendermint::LightClient as TmLightClient;
use crate::light_client::{LightClient, Verified};
use crate::util::pretty::{
    PrettyIdentifiedChannel, PrettyIdentifiedClientState, PrettyIdentifiedConnection,
};
use futures::Future;
use http::Uri;
use ibc_proto::protobuf::Protobuf;
use ibc_relayer_types::clients::ics07_tendermint::client_state::{
    AllowUpdate, ClientState as TmClientState,
};
use ibc_relayer_types::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc_relayer_types::clients::ics07_tendermint::header::Header as TmHeader;
use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics03_connection::connection::{
    ConnectionEnd, IdentifiedConnectionEnd,
};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId, ConnectionId};
use ibc_relayer_types::core::ics24_host::path::{
    AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath, CommitmentsPath,
    ConnectionsPath, ReceiptsPath, SeqRecvsPath,
};
use ibc_relayer_types::core::ics24_host::Path;
use ibc_relayer_types::Height as ICSHeight;
use tendermint::node::info::TxIndexStatus;
use tendermint::time::Time as TmTime;
use tendermint_light_client::verifier::types::LightBlock as TmLightBlock;
use tendermint_rpc::client::CompatMode;
use tendermint_rpc::endpoint::status;
use tendermint_rpc::{Client, HttpClient};
use tokio::runtime::Runtime as TokioRuntime;
use tracing::{error, trace, warn};

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
    pub(super) config: ChainConfig,
    pub(super) rpc_client: HttpClient,
    compat_mode: CompatMode,
    grpc_addr: Uri,
    light_client: TmLightClient,
    rt: Arc<TokioRuntime>,
    keybase: KeyRing<Secp256k1KeyPair>,

    tx_monitor_cmd: Option<TxEventSourceCmd>,
}

impl PenumbraChain {
    fn init_event_source(&mut self) -> Result<TxEventSourceCmd, Error> {
        crate::time!(
            "init_event_source",
            {
                "src_chain": self.config().id.to_string(),
            }
        );

        use crate::config::EventSourceMode as Mode;

        let (event_source, monitor_tx) = match &self.config.event_source {
            Mode::Push { url, batch_delay } => EventSource::websocket(
                self.config.id.clone(),
                url.clone(),
                self.compat_mode,
                *batch_delay,
                self.rt.clone(),
            ),
            Mode::Pull { interval } => EventSource::rpc(
                self.config.id.clone(),
                self.rpc_client.clone(),
                *interval,
                self.rt.clone(),
            ),
        }
        .map_err(Error::event_source)?;

        thread::spawn(move || event_source.run());

        Ok(monitor_tx)
    }
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
        let keybase =
            crate::keyring::KeyRing::new_secp256k1(Store::Test, "test", &config.id, &None).unwrap();

        let chain = Self {
            config,
            rpc_client,
            compat_mode,
            grpc_addr,
            light_client,
            rt,
            keybase,
            tx_monitor_cmd: None,
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
        let tx_monitor_cmd = match &self.tx_monitor_cmd {
            Some(tx_monitor_cmd) => tx_monitor_cmd,
            None => {
                let tx_monitor_cmd = self.init_event_source()?;
                self.tx_monitor_cmd = Some(tx_monitor_cmd);
                self.tx_monitor_cmd.as_ref().unwrap()
            }
        };

        let subscription = tx_monitor_cmd.subscribe().map_err(Error::event_source)?;
        Ok(subscription)
    }

    fn keybase(&self) -> &crate::keyring::KeyRing<Self::SigningKeyPair> {
        return &self.keybase;
    }

    fn keybase_mut(&mut self) -> &mut crate::keyring::KeyRing<Self::SigningKeyPair> {
        todo!()
    }

    fn get_signer(&self) -> Result<ibc_relayer_types::signer::Signer, crate::error::Error> {
        Ok(Signer::dummy())
    }

    fn ibc_version(&self) -> Result<Option<semver::Version>, crate::error::Error> {
        todo!()
    }

    fn send_messages_and_wait_commit(
        &mut self,
        tracked_msgs: crate::chain::tracking::TrackedMsgs,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, crate::error::Error> {
        let runtime = self.rt.clone();

        runtime.block_on(self.do_send_messages_and_wait_commit(tracked_msgs))
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: crate::chain::tracking::TrackedMsgs,
    ) -> Result<Vec<tendermint_rpc::endpoint::broadcast::tx_sync::Response>, crate::error::Error>
    {
        let runtime = self.rt.clone();

        runtime.block_on(self.do_send_messages_and_wait_check_tx(tracked_msgs))
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
        _key_name: Option<&str>,
        _denom: Option<&str>,
    ) -> Result<crate::account::Balance, crate::error::Error> {
        todo!()
    }

    fn query_all_balances(
        &self,
        _key_name: Option<&str>,
    ) -> Result<Vec<crate::account::Balance>, crate::error::Error> {
        todo!()
    }

    fn query_denom_trace(
        &self,
        _hash: String,
    ) -> Result<crate::denom::DenomTrace, crate::error::Error> {
        todo!()
    }

    fn query_commitment_prefix(
        &self,
    ) -> Result<
        ibc_relayer_types::core::ics23_commitment::commitment::CommitmentPrefix,
        crate::error::Error,
    > {
        // This is hardcoded for now.
        Ok(b"ibc-data".to_vec().try_into().unwrap())
    }

    fn query_application_status(
        &self,
    ) -> Result<crate::chain::endpoint::ChainStatus, crate::error::Error> {
        crate::time!(
            "query_application_status",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_application_status");

        // We cannot rely on `/status` endpoint to provide details about the latest block.
        // Instead, we need to pull block height via `/abci_info` and then fetch block
        // metadata at the given height via `/blockchain` endpoint.
        let abci_info = self
            .block_on(self.rpc_client.abci_info())
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        // Query `/header` endpoint to pull the latest block that the application committed.
        let response = self
            .block_on(self.rpc_client.header(abci_info.last_block_height))
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        let height = ICSHeight::new(
            ChainId::chain_version(response.header.chain_id.as_str()),
            u64::from(abci_info.last_block_height),
        )
        .map_err(|_| Error::invalid_height_no_source())?;

        let timestamp = response.header.time.into();
        Ok(ChainStatus { height, timestamp })
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
        crate::time!(
            "query_client_state",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_client_state");

        let res = self.query(
            ClientStatePath(request.client_id.clone()),
            request.height,
            matches!(include_proof, IncludeProof::Yes),
        )?;
        let client_state = AnyClientState::decode_vec(&res.value).map_err(Error::decode)?;

        match include_proof {
            IncludeProof::Yes => {
                let proof = res.proof.ok_or_else(Error::empty_response_proof)?;
                Ok((client_state, Some(proof)))
            }
            IncludeProof::No => Ok((client_state, None)),
        }
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
        crate::time!(
             "query_consensus_state",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_consensus_state");

        let res = self.query(
            ClientConsensusStatePath {
                client_id: request.client_id.clone(),
                epoch: request.consensus_height.revision_number(),
                height: request.consensus_height.revision_height(),
            },
            request.query_height,
            matches!(include_proof, IncludeProof::Yes),
        )?;

        let consensus_state = AnyConsensusState::decode_vec(&res.value).map_err(Error::decode)?;

        if !matches!(consensus_state, AnyConsensusState::Tendermint(_)) {
            return Err(Error::consensus_state_type_mismatch(
                ClientType::Tendermint,
                consensus_state.client_type(),
            ));
        }

        match include_proof {
            IncludeProof::Yes => {
                let proof = res.proof.ok_or_else(Error::empty_response_proof)?;
                Ok((consensus_state, Some(proof)))
            }
            IncludeProof::No => Ok((consensus_state, None)),
        }
    }

    fn query_consensus_state_heights(
        &self,
        _request: crate::chain::requests::QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ibc_relayer_types::Height>, crate::error::Error> {
        todo!()
    }

    fn query_upgraded_client_state(
        &self,
        _request: crate::chain::requests::QueryUpgradedClientStateRequest,
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
        _request: crate::chain::requests::QueryUpgradedConsensusStateRequest,
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
        crate::time!(
            "query_connections",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_connections");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::connection::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let response = self
            .block_on(client.connections(request))
            .map_err(|e| Error::grpc_status(e, "query_connections".to_owned()))?
            .into_inner();

        let connections = response
            .connections
            .into_iter()
            .filter_map(|co| {
                IdentifiedConnectionEnd::try_from(co.clone())
                    .map_err(|e| {
                        warn!(
                            "connection with ID {} failed parsing. Error: {}",
                            PrettyIdentifiedConnection(&co),
                            e
                        )
                    })
                    .ok()
            })
            .collect();

        Ok(connections)
    }

    fn query_client_connections(
        &self,
        request: crate::chain::requests::QueryClientConnectionsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics24_host::identifier::ConnectionId>,
        crate::error::Error,
    > {
        crate::time!(
            "query_client_connections",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_client_connections");

        let connections = self.query_connections(QueryConnectionsRequest {
            pagination: Default::default(),
        })?;

        let mut client_conns = vec![];
        for connection in connections {
            if connection
                .connection_end
                .client_id_matches(&request.client_id)
            {
                client_conns.push(connection.connection_id);
            }
        }

        Ok(client_conns)
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
        crate::time!(
            "query_connection",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_connection");

        async fn do_query_connection(
            config: &ChainConfig,
            grpc_addr: Uri,
            connection_id: &ConnectionId,
        ) -> Result<ConnectionEnd, Error> {
            use ibc_proto::ibc::core::connection::v1 as connection;
            use tonic::IntoRequest;

            let mut client = connection::query_client::QueryClient::connect(grpc_addr)
                .await
                .map_err(Error::grpc_transport)?;

            client = client
                .max_decoding_message_size(config.max_grpc_decoding_size.get_bytes() as usize);

            let request = connection::QueryConnectionRequest {
                connection_id: connection_id.to_string(),
            }
            .into_request();

            let response = client.connection(request).await.map_err(|e| {
                if e.code() == tonic::Code::NotFound {
                    Error::connection_not_found(connection_id.clone())
                } else {
                    Error::grpc_status(e, "query_connection".to_owned())
                }
            })?;

            match response.into_inner().connection {
                Some(raw_connection) => {
                    let connection_end = raw_connection.try_into().map_err(Error::ics03)?;

                    Ok(connection_end)
                }
                None => {
                    // When no connection is found, the GRPC call itself should return
                    // the NotFound error code. Nevertheless even if the call is successful,
                    // the connection field may not be present, because in protobuf3
                    // everything is optional.
                    Err(Error::connection_not_found(connection_id.clone()))
                }
            }
        }

        match include_proof {
            IncludeProof::Yes => {
                let res = self.query(
                    ConnectionsPath(request.connection_id.clone()),
                    request.height,
                    true,
                )?;
                let connection_end =
                    ConnectionEnd::decode_vec(&res.value).map_err(Error::decode)?;

                Ok((
                    connection_end,
                    Some(res.proof.ok_or_else(Error::empty_response_proof)?),
                ))
            }
            IncludeProof::No => self
                .block_on(async {
                    do_query_connection(
                        &self.config,
                        self.grpc_addr.clone(),
                        &request.connection_id,
                    )
                    .await
                })
                .map(|conn_end| (conn_end, None)),
        }
    }

    fn query_connection_channels(
        &self,
        request: crate::chain::requests::QueryConnectionChannelsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics04_channel::channel::IdentifiedChannelEnd>,
        crate::error::Error,
    > {
        crate::time!(
            "query_connection_channels",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_connection_channels");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let response = self
            .block_on(client.connection_channels(request))
            .map_err(|e| Error::grpc_status(e, "query_connection_channels".to_owned()))?
            .into_inner();

        let channels = response
            .channels
            .into_iter()
            .filter_map(|ch| {
                IdentifiedChannelEnd::try_from(ch.clone())
                    .map_err(|e| {
                        warn!(
                            "channel with ID {} failed parsing. Error: {}",
                            PrettyIdentifiedChannel(&ch),
                            e
                        )
                    })
                    .ok()
            })
            .collect();
        Ok(channels)
    }

    fn query_channels(
        &self,
        request: crate::chain::requests::QueryChannelsRequest,
    ) -> Result<
        Vec<ibc_relayer_types::core::ics04_channel::channel::IdentifiedChannelEnd>,
        crate::error::Error,
    > {
        crate::time!(
            "query_channels",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_channels");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let response = self
            .block_on(client.channels(request))
            .map_err(|e| Error::grpc_status(e, "query_channels".to_owned()))?
            .into_inner();

        let channels = response
            .channels
            .into_iter()
            .filter_map(|ch| {
                IdentifiedChannelEnd::try_from(ch.clone())
                    .map_err(|e| {
                        warn!(
                            "channel with ID {} failed parsing. Error: {}",
                            PrettyIdentifiedChannel(&ch),
                            e
                        )
                    })
                    .ok()
            })
            .collect();

        Ok(channels)
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
        crate::time!(
            "query_channel",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_channel");

        let res = self.query(
            ChannelEndsPath(request.port_id, request.channel_id),
            request.height,
            matches!(include_proof, IncludeProof::Yes),
        )?;

        let channel_end = ChannelEnd::decode_vec(&res.value).map_err(Error::decode)?;

        match include_proof {
            IncludeProof::Yes => {
                let proof = res.proof.ok_or_else(Error::empty_response_proof)?;
                Ok((channel_end, Some(proof)))
            }
            IncludeProof::No => Ok((channel_end, None)),
        }
    }

    fn query_channel_client_state(
        &self,
        request: crate::chain::requests::QueryChannelClientStateRequest,
    ) -> Result<Option<crate::client_state::IdentifiedAnyClientState>, crate::error::Error> {
        crate::time!(
            "query_channel_client_state",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_channel_client_state");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let response = self
            .block_on(client.channel_client_state(request))
            .map_err(|e| Error::grpc_status(e, "query_channel_client_state".to_owned()))?
            .into_inner();

        let client_state: Option<IdentifiedAnyClientState> = response
            .identified_client_state
            .map_or_else(|| None, |proto_cs| proto_cs.try_into().ok());

        Ok(client_state)
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
        let res = self.query(
            CommitmentsPath {
                port_id: request.port_id,
                channel_id: request.channel_id,
                sequence: request.sequence,
            },
            request.height,
            matches!(include_proof, IncludeProof::Yes),
        )?;

        match include_proof {
            IncludeProof::Yes => {
                let proof = res.proof.ok_or_else(Error::empty_response_proof)?;

                Ok((res.value, Some(proof)))
            }
            IncludeProof::No => Ok((res.value, None)),
        }
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
        crate::time!(
            "query_packet_commitments",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_packet_commitments");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let response = self
            .block_on(client.packet_commitments(request))
            .map_err(|e| Error::grpc_status(e, "query_packet_commitments".to_owned()))?
            .into_inner();

        let mut commitment_sequences: Vec<Sequence> = response
            .commitments
            .into_iter()
            .map(|v| v.sequence.into())
            .collect();
        commitment_sequences.sort_unstable();

        let height = response
            .height
            .and_then(|raw_height| raw_height.try_into().ok())
            .ok_or_else(|| Error::grpc_response_param("height".to_string()))?;

        Ok((commitment_sequences, height))
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
        let res = self.query(
            ReceiptsPath {
                port_id: request.port_id,
                channel_id: request.channel_id,
                sequence: request.sequence,
            },
            request.height,
            matches!(include_proof, IncludeProof::Yes),
        )?;

        match include_proof {
            IncludeProof::Yes => {
                let proof = res.proof.ok_or_else(Error::empty_response_proof)?;

                Ok((res.value, Some(proof)))
            }
            IncludeProof::No => Ok((res.value, None)),
        }
    }

    fn query_unreceived_packets(
        &self,
        request: crate::chain::requests::QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>, crate::error::Error>
    {
        crate::time!(
            "query_unreceived_packets",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_unreceived_packets");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let mut response = self
            .block_on(client.unreceived_packets(request))
            .map_err(|e| Error::grpc_status(e, "query_unreceived_packets".to_owned()))?
            .into_inner();

        response.sequences.sort_unstable();
        Ok(response
            .sequences
            .into_iter()
            .map(|seq| seq.into())
            .collect())
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
        let res = self.query(
            AcksPath {
                port_id: request.port_id,
                channel_id: request.channel_id,
                sequence: request.sequence,
            },
            request.height,
            matches!(include_proof, IncludeProof::Yes),
        )?;

        match include_proof {
            IncludeProof::Yes => {
                let proof = res.proof.ok_or_else(Error::empty_response_proof)?;

                Ok((res.value, Some(proof)))
            }
            IncludeProof::No => Ok((res.value, None)),
        }
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
        crate::telemetry!(query, self.id(), "query_packet_acknowledgements");
        crate::time!(
            "query_packet_acknowledgements",
            {
                "src_chain": self.config().id.to_string(),
            }
        );

        if request.packet_commitment_sequences.is_empty() {
            return Ok((Vec::new(), self.query_chain_latest_height()?));
        }

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let response = self
            .block_on(client.packet_acknowledgements(request))
            .map_err(|e| Error::grpc_status(e, "query_packet_acknowledgements".to_owned()))?
            .into_inner();

        let acks_sequences = response
            .acknowledgements
            .into_iter()
            .map(|v| v.sequence.into())
            .collect();

        let height = response
            .height
            .and_then(|raw_height| raw_height.try_into().ok())
            .ok_or_else(|| Error::grpc_response_param("height".to_string()))?;

        Ok((acks_sequences, height))
    }

    fn query_unreceived_acknowledgements(
        &self,
        request: crate::chain::requests::QueryUnreceivedAcksRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics04_channel::packet::Sequence>, crate::error::Error>
    {
        crate::time!(
            "query_unreceived_acknowledgements",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_unreceived_acknowledgements");

        let mut client = self
            .block_on(
                ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                    self.grpc_addr.clone(),
                ),
            )
            .map_err(Error::grpc_transport)?;

        client = client
            .max_decoding_message_size(self.config().max_grpc_decoding_size.get_bytes() as usize);

        let request = tonic::Request::new(request.into());

        let mut response = self
            .block_on(client.unreceived_acks(request))
            .map_err(|e| Error::grpc_status(e, "query_unreceived_acknowledgements".to_owned()))?
            .into_inner();

        response.sequences.sort_unstable();
        Ok(response
            .sequences
            .into_iter()
            .map(|seq| seq.into())
            .collect())
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
        crate::time!(
            "query_next_sequence_receive",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_next_sequence_receive");

        match include_proof {
            IncludeProof::Yes => {
                let res = self.query(
                    SeqRecvsPath(request.port_id, request.channel_id),
                    request.height,
                    true,
                )?;

                // Note: We expect the return to be a u64 encoded in big-endian. Refer to ibc-go:
                // https://github.com/cosmos/ibc-go/blob/25767f6bdb5bab2c2a116b41d92d753c93e18121/modules/core/04-channel/client/utils/utils.go#L191
                if res.value.len() != 8 {
                    return Err(Error::query("next_sequence_receive".into()));
                }
                let seq: Sequence = Bytes::from(res.value).get_u64().into();

                let proof = res.proof.ok_or_else(Error::empty_response_proof)?;

                Ok((seq, Some(proof)))
            }
            IncludeProof::No => {
                let mut client = self
                    .block_on(
                        ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
                            self.grpc_addr.clone(),
                        ),
                    )
                    .map_err(Error::grpc_transport)?;

                client = client.max_decoding_message_size(
                    self.config().max_grpc_decoding_size.get_bytes() as usize,
                );

                let request = tonic::Request::new(request.into());

                let response = self
                    .block_on(client.next_sequence_receive(request))
                    .map_err(|e| Error::grpc_status(e, "query_next_sequence_receive".to_owned()))?
                    .into_inner();

                Ok((Sequence::from(response.next_sequence_receive), None))
            }
        }
    }

    fn query_txs(
        &self,
        request: crate::chain::requests::QueryTxRequest,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, crate::error::Error> {
        crate::time!("query_txs",
        {
            "src_chain": self.config().id.to_string(),
        });
        crate::telemetry!(query, self.id(), "query_txs");

        self.block_on(query_txs(
            self.id(),
            &self.rpc_client,
            &self.config.rpc_addr,
            request,
        ))
    }

    fn query_packet_events(
        &self,
        mut request: crate::chain::requests::QueryPacketEventDataRequest,
    ) -> Result<Vec<crate::event::IbcEventWithHeight>, crate::error::Error> {
        crate::time!(
            "query_packet_events",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_packet_events");

        tracing::info!(?request);

        match request.height {
            // Usage note: `Qualified::Equal` is currently only used in the call hierarchy involving
            // the CLI methods, namely the CLI for `tx packet-recv` and `tx packet-ack` when the
            // user passes the flag `packet-data-query-height`.
            Qualified::Equal(_) => self.block_on(query_packets_from_block(
                self.id(),
                &self.rpc_client,
                &self.config.rpc_addr,
                &request,
            )),
            Qualified::SmallerEqual(_) => {
                let tx_events = self.block_on(query_packets_from_txs(
                    self.id(),
                    &self.rpc_client,
                    &self.config.rpc_addr,
                    &request,
                ))?;

                let recvd_sequences: Vec<_> = tx_events
                    .iter()
                    .filter_map(|eh| eh.event.packet().map(|p| p.sequence))
                    .collect();

                request
                    .sequences
                    .retain(|seq| !recvd_sequences.contains(seq));

                let (start_block_events, end_block_events) = if !request.sequences.is_empty() {
                    self.query_packets_from_blocks(&request)?
                } else {
                    Default::default()
                };

                trace!("start_block_events {:?}", start_block_events);
                trace!("tx_events {:?}", tx_events);
                trace!("end_block_events {:?}", end_block_events);

                // Events should be ordered in the following fashion,
                // for any two blocks b1, b2 at height h1, h2 with h1 < h2:
                // b1.start_block_events
                // b1.tx_events
                // b1.end_block_events
                // b2.start_block_events
                // b2.tx_events
                // b2.end_block_events
                //
                // As of now, we just sort them by sequence number which should
                // yield a similar result and will revisit this approach in the future.
                let mut events = vec![];
                events.extend(start_block_events);
                events.extend(tx_events);
                events.extend(end_block_events);

                sort_events_by_sequence(&mut events);

                Ok(events)
            }
        }
    }

    fn query_host_consensus_state(
        &self,
        _request: crate::chain::requests::QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, crate::error::Error> {
        todo!()
    }

    fn build_client_state(
        &self,
        height: ibc_relayer_types::Height,
        settings: crate::chain::client::ClientSettings,
    ) -> Result<Self::ClientState, crate::error::Error> {
        let ClientSettings::Tendermint(settings) = settings;
        // two hour duration
        let two_hours = Duration::from_secs(2 * 60 * 60);
        let unbonding_period = two_hours;
        let trusting_period_default = 2 * unbonding_period / 3;
        let trusting_period = settings
            .trusting_period
            .unwrap_or_else(|| trusting_period_default);

        let proof_specs = self.config.proof_specs.clone().unwrap_or_else(|| {
            if self.config.penumbra_use_prehash_key_before_comparison {
                crate::chain::penumbra::proofspec::penumbra_proof_spec_with_prehash()
            } else {
                crate::chain::penumbra::proofspec::penumbra_proof_spec_no_prehash()
            }
        });

        // Build the client state.
        TmClientState::new(
            self.id().clone(),
            settings.trust_threshold,
            trusting_period,
            unbonding_period,
            settings.max_clock_drift,
            height,
            proof_specs,
            vec!["upgrade".to_string(), "upgradedIBCState".to_string()],
            AllowUpdate {
                after_expiry: true,
                after_misbehaviour: true,
            },
        )
        .map_err(Error::ics07)
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, crate::error::Error> {
        crate::time!(
            "build_consensus_state",
            {
                "src_chain": self.config().id.to_string(),
            }
        );

        Ok(TmConsensusState::from(light_block.signed_header.header))
    }

    fn build_header(
        &mut self,
        trusted_height: ibc_relayer_types::Height,
        target_height: ibc_relayer_types::Height,
        client_state: &crate::client_state::AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), crate::error::Error> {
        crate::time!(
            "build_header",
            {
                "src_chain": self.config().id.to_string(),
            }
        );

        let now = self.chain_status()?.sync_info.latest_block_time;

        // Get the light block at target_height from chain.
        let Verified { target, supporting } = self.light_client.header_and_minimal_set(
            trusted_height,
            target_height,
            client_state,
            now,
        )?;

        Ok((target, supporting))
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        _channel_id: &ibc_relayer_types::core::ics24_host::identifier::ChannelId,
        _port_id: &ibc_relayer_types::core::ics24_host::identifier::PortId,
        _counterparty_payee: &ibc_relayer_types::signer::Signer,
    ) -> Result<(), crate::error::Error> {
        todo!()
    }

    fn cross_chain_query(
        &self,
        _requests: Vec<crate::chain::requests::CrossChainQueryRequest>,
    ) -> Result<
        Vec<ibc_relayer_types::applications::ics31_icq::response::CrossChainQueryResponse>,
        crate::error::Error,
    > {
        todo!()
    }

    fn query_incentivized_packet(
        &self,
        _request: ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketRequest,
    ) -> Result<ibc_proto::ibc::apps::fee::v1::QueryIncentivizedPacketResponse, crate::error::Error>
    {
        todo!()
    }
}

impl PenumbraChain {
    /// Run a future to completion on the Tokio runtime.
    pub(super) fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }
    /// Query the chain's latest height
    pub fn query_chain_latest_height(&self) -> Result<ICSHeight, Error> {
        crate::time!(
            "query_latest_height",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_latest_height");

        let status = self.rt.block_on(query_status(
            self.id(),
            &self.rpc_client,
            &self.config.rpc_addr,
        ))?;

        Ok(status.height)
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

    fn query(
        &self,
        data: impl Into<Path>,
        height_query: QueryHeight,
        prove: bool,
    ) -> Result<QueryResponse, Error> {
        crate::time!("query",
        {
            "src_chain": self.config().id.to_string(),
        });

        let data = data.into();
        if !data.is_provable() & prove {
            return Err(Error::private_store());
        }

        let response = self.block_on(abci_query(
            &self.rpc_client,
            &self.config.rpc_addr,
            "state/key".to_string(),
            data.to_string(),
            height_query.into(),
            prove,
        ))?;

        // TODO - Verify response proof, if requested.
        if prove {}

        Ok(response)
    }

    /// Performs a health check on a Penumbra chain.
    ///
    /// This health check checks on the following in this order:
    /// 1. Checks on the self-reported health endpoint.
    /// 2. Checks that transaction indexing is enabled.
    /// 3. Checks that the self-reported chain ID matches the configured one.
    fn do_health_check(&self) -> Result<(), Error> {
        let chain_id = self.id();
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
