use bytes::{Buf, Bytes};
use ibc_relayer_types::core::ics23_commitment::specs::ProofSpecs;
use ibc_relayer_types::signer::Signer;
use penumbra_proto::core::ibc::v1alpha1::IbcAction;
use prost::Message;
use rand::Rng;
use std::thread;
use std::time::Duration;
use std::{str::FromStr, sync::Arc};

use crate::chain::client::ClientSettings;
use crate::chain::cosmos::query::status::query_status;
use crate::chain::cosmos::query::QueryResponse;
use crate::chain::cosmos::types::tx::{TxStatus, TxSyncResult};
use crate::chain::cosmos::wait::wait_for_block_commits;
use crate::chain::endpoint::{ChainEndpoint, ChainStatus, HealthCheck};
use crate::event::source::{EventSource, TxEventSourceCmd};
use tendermint_rpc::endpoint::broadcast::tx_sync::Response;

use crate::chain::requests::{
    IncludeProof, QueryClientStatesRequest, QueryConnectionsRequest, QueryHeight,
};
use crate::chain::tracking::TrackedMsgs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::config::ChainConfig;
use crate::consensus_state::AnyConsensusState;
use crate::error::Error;
use crate::event::IbcEventWithHeight;
use crate::keyring::{KeyRing, Secp256k1KeyPair, SigningKeyPair, Store};
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
use ibc_relayer_types::core::ics02_client::error::Error as ClientError;
use ibc_relayer_types::core::ics03_connection::connection::{
    ConnectionEnd, IdentifiedConnectionEnd,
};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics23_commitment::merkle::convert_tm_to_ics_merkle_proof;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId, ConnectionId};
use ibc_relayer_types::core::ics24_host::path::{
    AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath, CommitmentsPath,
    ConnectionsPath, ReceiptsPath, SeqRecvsPath,
};
use ibc_relayer_types::core::ics24_host::{Path, IBC_QUERY_PATH};
use ibc_relayer_types::Height as ICSHeight;
use once_cell::sync::Lazy;
use tendermint::block::Height;
use tendermint::node::info::TxIndexStatus;
use tendermint::time::Time as TmTime;
use tendermint_light_client::verifier::types::LightBlock as TmLightBlock;
use tendermint_rpc::client::CompatMode;
use tendermint_rpc::endpoint::status;
use tendermint_rpc::{Client, HttpClient, Url};
use tokio::runtime::Runtime as TokioRuntime;
use tracing::{error, info, instrument, trace, warn};

pub static PENUMBRA_PROOF_SPECS: Lazy<ProofSpecs> =
    Lazy::new(|| vec![jmt::ics23_spec(), apphash_spec()].into());

/// this is a proof spec for computing Penumbra's AppHash, which is defined as
/// SHA256("PenumbraAppHash" || jmt.root()). In ICS/IBC terms, this applies a single global prefix
/// to Penumbra's state. Having a stable merkle prefix is currently required for our IBC
/// counterparties to verify our proofs.
fn apphash_spec() -> ics23::ProofSpec {
    ics23::ProofSpec {
        // the leaf hash is simply H(key || value)
        leaf_spec: Some(ics23::LeafOp {
            prefix: vec![],
            hash: ics23::HashOp::Sha256.into(),
            length: ics23::LengthOp::NoPrefix.into(),
            prehash_key: ics23::HashOp::NoHash.into(),
            prehash_value: ics23::HashOp::NoHash.into(),
        }),
        // NOTE: we don't actually use any InnerOps.
        inner_spec: Some(ics23::InnerSpec {
            hash: ics23::HashOp::Sha256.into(),
            child_order: vec![0, 1],
            child_size: 32,
            empty_child: vec![],
            min_prefix_length: 0,
            max_prefix_length: 0,
        }),
        min_depth: 0,
        max_depth: 1,
        prehash_key_before_comparison: true,
    }
}

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

/// Perform a generic `abci_query`, and return the corresponding deserialized response data.
pub async fn abci_query(
    rpc_client: &HttpClient,
    rpc_address: &Url,
    path: String,
    data: String,
    height: Height,
    prove: bool,
) -> Result<QueryResponse, Error> {
    let height = if height.value() == 0 {
        None
    } else {
        Some(height)
    };

    // Use the Tendermint-rs RPC client to do the query.
    let response = rpc_client
        .abci_query(Some(path), data.into_bytes(), height, prove)
        .await
        .map_err(|e| Error::rpc(rpc_address.clone(), e))?;

    if !response.code.is_ok() {
        // Fail with response log.
        return Err(Error::abci_query(response));
    }

    if prove && response.proof.is_none() {
        // Fail due to empty proof
        return Err(Error::empty_response_proof());
    }

    let proof = response
        .proof
        .map(|p| convert_tm_to_ics_merkle_proof(&p))
        .transpose()
        .map_err(Error::ics23)?;

    let response = QueryResponse {
        value: response.value,
        height: response.height,
        proof,
    };

    Ok(response)
}

pub fn key_pair_to_signer(key_pair: &Secp256k1KeyPair) -> Result<Signer, Error> {
    let signer = key_pair
        .account()
        .parse()
        .map_err(|e| Error::ics02(ClientError::signer(e)))?;

    Ok(signer)
}

pub struct PenumbraChain {
    config: ChainConfig,
    rpc_client: HttpClient,
    compat_mode: CompatMode,
    grpc_addr: Uri,
    light_client: TmLightClient,
    rt: Arc<TokioRuntime>,
    keybase: KeyRing<Secp256k1KeyPair>,

    tx_monitor_cmd: Option<TxEventSourceCmd>,
}

impl PenumbraChain {
    async fn get_anchor(
        &self,
    ) -> Result<penumbra_proto::core::crypto::v1alpha1::MerkleRoot, Error> {
        let status = self
            .rpc_client
            .status()
            .await
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        let path = format!("sct/anchor/0");
        let height_u64 = status.sync_info.latest_block_height.value();
        let height_tm = Height::try_from(height_u64 - 1).unwrap();

        let res = self
            .rpc_client
            .abci_query(
                Some("state/key".to_string()),
                path.into_bytes(),
                Some(height_tm),
                false,
            )
            .await
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        println!("RES: {:?}", res);

        Ok(penumbra_proto::core::crypto::v1alpha1::MerkleRoot {
            inner: res.value[2..].into(),
        })
    }
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
    #[instrument(
        name = "send_messages_and_wait_commit",
        level = "error",
        skip_all,
        fields(
            chain = %self.id(),
            tracking_id = %tracked_msgs.tracking_id()
        ),
    )]
    async fn do_send_messages_and_wait_commit(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        crate::time!(
            "send_messages_and_wait_commit",
            {
                "src_chain": self.config().id.to_string(),
            }
        );

        let last_anchor = self.get_anchor().await?;

        let proto_msgs = tracked_msgs.msgs;

        let mut ibc_actions = vec![];

        for msg in proto_msgs {
            //cursed
            ibc_actions.push(penumbra_proto::core::transaction::v1alpha1::Action {
                action: Some(
                    penumbra_proto::core::transaction::v1alpha1::action::Action::IbcAction(
                        IbcAction {
                            raw_action: Some(pbjson_types::Any {
                                type_url: msg.type_url,
                                value: msg.value.into(),
                            }),
                        },
                    ),
                ),
            });
        }

        let tx_body = penumbra_proto::core::transaction::v1alpha1::TransactionBody {
            actions: ibc_actions.clone(),
            fee: Some(penumbra_proto::core::crypto::v1alpha1::Fee {
                amount: Some(penumbra_proto::core::crypto::v1alpha1::Amount { lo: 0, hi: 0 }),
                asset_id: None,
            }),
            memo_data: Some(penumbra_proto::core::transaction::v1alpha1::MemoData {
                encrypted_memo: vec![].into(),
            }),
            transaction_parameters: Some(
                penumbra_proto::core::transaction::v1alpha1::TransactionParameters {
                    expiry_height: 0,
                    chain_id: "".to_string(),
                },
            ),
            detection_data: None,
        };

        let tx = penumbra_proto::core::transaction::v1alpha1::Transaction {
            body: Some(tx_body),
            binding_sig: vec![0; 64].into(), // cool signature
            anchor: Some(last_anchor),
        };

        let tx_bytes = tx.encode_to_vec();

        // submit tx

        let res = self
            .rpc_client
            .broadcast_tx_sync(tx_bytes)
            .await
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        let txsync_res = response_to_tx_sync_result(&self.config.id, ibc_actions.len(), res);

        let mut txsync_responses = vec![txsync_res];

        // wait for one commit
        wait_for_block_commits(
            &self.config.id,
            &self.rpc_client,
            &self.config.rpc_addr,
            &self.config.rpc_timeout,
            &mut txsync_responses,
        )
        .await?;

        // NOTE: this is to deal with proxy inconsistency. we wait for two additional blocks to be sure.
        let start_height = self
            .rpc_client
            .status()
            .await
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?
            .sync_info
            .latest_block_height;
        let mut current_height = start_height;

        while current_height.value() - start_height.value() < 2 {
            let status = self
                .rpc_client
                .status()
                .await
                .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

            current_height = status.sync_info.latest_block_height;
        }

        let events = txsync_responses
            .into_iter()
            .flat_map(|el| el.events)
            .collect();

        Ok(events)
    }
}

fn response_to_tx_sync_result(
    chain_id: &ChainId,
    message_count: usize,
    response: Response,
) -> TxSyncResult {
    if response.code.is_err() {
        // Note: we don't have any height information in this case. This hack will fix itself
        // once we remove the `ChainError` event (which is not actually an event)
        let height = ibc_relayer_types::Height::new(chain_id.version(), 1).unwrap();

        let events_per_tx = vec![IbcEventWithHeight::new(ibc_relayer_types::events::IbcEvent::ChainError(format!(
            "check_tx (broadcast_tx_sync) on chain {} for Tx hash {} reports error: code={:?}, log={:?}",
            chain_id, response.hash, response.code, response.log
        )), height); message_count];

        TxSyncResult {
            response,
            events: events_per_tx,
            status: TxStatus::ReceivedResponse,
        }
    } else {
        TxSyncResult {
            response,
            events: Vec::new(),
            status: TxStatus::Pending { message_count },
        }
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
        // This is hardcoded for now.
        Ok("PenumbraAppHash".as_bytes().to_vec().try_into().unwrap())
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
            height_query: QueryHeight,
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
                        request.height,
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
        let ClientSettings::Tendermint(settings) = settings;
        // two hour duration
        let two_hours = Duration::from_secs(2 * 60 * 60);
        let unbonding_period = two_hours;
        let trusting_period_default = 2 * unbonding_period / 3;
        let trusting_period = settings
            .trusting_period
            .unwrap_or_else(|| trusting_period_default);

        let proof_specs = self
            .config
            .proof_specs
            .clone()
            .unwrap_or(vec![jmt::ics23_spec(), apphash_spec()].into());

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
