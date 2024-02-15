use anyhow::Context;
use futures::{FutureExt, StreamExt, TryStreamExt};
use http::Uri;
use ibc_proto::ics23;
use ibc_relayer_types::core::ics23_commitment::commitment::CommitmentProofBytes;
use once_cell::sync::Lazy;
use penumbra_proto::core::component::ibc::v1::IbcRelay as ProtoIbcRelay;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::chain::client::ClientSettings;
use crate::chain::requests::IncludeProof;
use crate::chain::requests::*;
use crate::chain::tracking::TrackedMsgs;
use crate::client_state::{AnyClientState, IdentifiedAnyClientState};
use crate::consensus_state::AnyConsensusState;
use crate::event::source::{EventSource, TxEventSourceCmd};
use crate::event::{ibc_event_try_from_abci_event, IbcEventWithHeight};
use crate::light_client::tendermint::LightClient as TmLightClient;
use crate::util::pretty::{
    PrettyIdentifiedChannel, PrettyIdentifiedClientState, PrettyIdentifiedConnection,
};
use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
use ibc_proto::ibc::core::{
    channel::v1::query_client::QueryClient as IbcChannelQueryClient,
    client::v1::query_client::QueryClient as IbcClientQueryClient,
    connection::v1::query_client::QueryClient as IbcConnectionQueryClient,
};
use ibc_relayer_types::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use ibc_relayer_types::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc_relayer_types::clients::ics07_tendermint::header::Header as TmHeader;
use ibc_relayer_types::core::ics02_client::client_type::ClientType;
use ibc_relayer_types::core::ics03_connection::connection::{
    ConnectionEnd, IdentifiedConnectionEnd,
};
use ibc_relayer_types::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc_relayer_types::core::ics04_channel::packet::Sequence;
use ibc_relayer_types::core::ics23_commitment::merkle::MerkleProof;
use ibc_relayer_types::core::ics24_host::identifier::ClientId;
use ibc_relayer_types::Height as ICSHeight;
use penumbra_fee::FeeTier;
use penumbra_ibc::IbcRelay;
use penumbra_keys::keys::AddressIndex;
use penumbra_proto::box_grpc_svc::{self, BoxGrpcService};
use penumbra_proto::{
    custody::v1::{
        custody_service_client::CustodyServiceClient, custody_service_server::CustodyServiceServer,
    },
    view::v1::{
        broadcast_transaction_response::Status as BroadcastStatus,
        view_service_client::ViewServiceClient, view_service_server::ViewServiceServer,
        GasPricesRequest,
    },
};
use penumbra_transaction::gas::GasCost;
use penumbra_transaction::memo::MemoPlaintext;
use penumbra_view::{ViewClient, ViewServer};
use penumbra_wallet::plan::Planner;
use signature::rand_core::OsRng;

use tendermint::time::Time as TmTime;
use tendermint_light_client::verifier::types::LightBlock as TmLightBlock;
use tendermint_rpc::{Client as _, HttpClient};
use tokio::runtime::Runtime as TokioRuntime;
use tonic::IntoRequest;

use crate::{
    chain::{
        endpoint::{ChainEndpoint, HealthCheck},
        handle::Subscription,
    },
    config::{ChainConfig, Error as ConfigError},
    error::Error,
    keyring::Secp256k1KeyPair,
};

use super::config::{self, PenumbraConfig};

pub struct PenumbraChain {
    config: PenumbraConfig,
    rt: Arc<TokioRuntime>,

    view_client: ViewServiceClient<BoxGrpcService>,
    custody_client: CustodyServiceClient<BoxGrpcService>,

    ibc_client_grpc_client: IbcClientQueryClient<tonic::transport::Channel>,
    ibc_connection_grpc_client: IbcConnectionQueryClient<tonic::transport::Channel>,
    ibc_channel_grpc_client: IbcChannelQueryClient<tonic::transport::Channel>,

    tendermint_rpc_client: HttpClient,
    tendermint_light_client: TmLightClient,

    tx_monitor_cmd: Option<TxEventSourceCmd>,
}

impl PenumbraChain {
    fn init_event_source(&mut self) -> Result<TxEventSourceCmd, Error> {
        crate::time!(
            "init_event_source",
            {
                "src_chain": self.config().id().to_string(),
            }
        );

        use crate::config::EventSourceMode as Mode;

        let (event_source, monitor_tx) = match &self.config.event_source {
            Mode::Pull { interval } => EventSource::rpc(
                self.config.id.clone(),
                self.tendermint_rpc_client.clone(),
                *interval,
                self.rt.clone(),
            ),
            _ => unimplemented!(),
        }
        .map_err(Error::event_source)?;

        thread::spawn(move || event_source.run());

        Ok(monitor_tx)
    }

    fn chain_status(&self) -> Result<tendermint_rpc::endpoint::status::Response, Error> {
        let status = self
            .rt
            .block_on(self.tendermint_rpc_client.status())
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        Ok(status)
    }

    async fn query_packets_from_blocks(
        &self,
        request: &QueryPacketEventDataRequest,
    ) -> Result<(Vec<IbcEventWithHeight>, Vec<IbcEventWithHeight>), Error> {
        use crate::chain::cosmos::query::packet_query;

        let mut begin_block_events = vec![];
        let mut end_block_events = vec![];

        for seq in request.sequences.iter().copied() {
            let response = self
                .tendermint_rpc_client
                .block_search(
                    packet_query(request, seq),
                    // We only need the first page
                    1,
                    // There should only be a single match for this query, but due to
                    // the fact that the indexer treat the query as a disjunction over
                    // all events in a block rather than a conjunction over a single event,
                    // we may end up with partial matches and therefore have to account for
                    // that by fetching multiple results and filter it down after the fact.
                    // In the worst case we get N blocks where N is the number of channels,
                    // but 10 seems to work well enough in practice while keeping the response
                    // size, and therefore pressure on the node, fairly low.
                    10,
                    // We could pick either ordering here, since matching blocks may be at pretty
                    // much any height relative to the target blocks, so we went with most recent
                    // blocks first.
                    tendermint_rpc::Order::Descending,
                )
                .await
                .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

            for block in response.blocks.into_iter().map(|response| response.block) {
                let response_height =
                    ICSHeight::new(self.id().version(), u64::from(block.header.height))
                        .map_err(|_| Error::invalid_height_no_source())?;

                if let QueryHeight::Specific(query_height) = request.height.get() {
                    if response_height > query_height {
                        continue;
                    }
                }

                // `query_packet_from_block` retrieves the begin and end block events
                // and filter them to retain only those matching the query
                let (new_begin_block_events, new_end_block_events) =
                    self.query_packet_from_block(request, &[seq], &response_height)?;

                begin_block_events.extend(new_begin_block_events);
                end_block_events.extend(new_end_block_events);
            }
        }

        Ok((begin_block_events, end_block_events))
    }

    pub(super) fn query_packet_from_block(
        &self,
        request: &QueryPacketEventDataRequest,
        seqs: &[Sequence],
        block_height: &ICSHeight,
    ) -> Result<(Vec<IbcEventWithHeight>, Vec<IbcEventWithHeight>), Error> {
        use crate::chain::cosmos::query::tx::filter_matching_event;

        let mut begin_block_events = vec![];
        let mut end_block_events = vec![];

        let tm_height =
            tendermint::block::Height::try_from(block_height.revision_height()).unwrap();

        let response = self
            .rt
            .block_on(self.tendermint_rpc_client.block_results(tm_height))
            .map_err(|e| Error::rpc(self.config.rpc_addr.clone(), e))?;

        let response_height = ICSHeight::new(self.id().version(), u64::from(response.height))
            .map_err(|_| Error::invalid_height_no_source())?;

        begin_block_events.append(
            &mut response
                .begin_block_events
                .unwrap_or_default()
                .iter()
                .filter_map(|ev| filter_matching_event(ev, request, seqs))
                .map(|ev| IbcEventWithHeight::new(ev, response_height))
                .collect(),
        );

        end_block_events.append(
            &mut response
                .end_block_events
                .unwrap_or_default()
                .iter()
                .filter_map(|ev| filter_matching_event(ev, request, seqs))
                .map(|ev| IbcEventWithHeight::new(ev, response_height))
                .collect(),
        );

        Ok((begin_block_events, end_block_events))
    }

    async fn broadcast_messages(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        let gas_prices = self
            .view_client
            .gas_prices(GasPricesRequest {})
            .await
            .unwrap()
            .into_inner()
            .gas_prices
            .expect("gas prices must be available")
            .try_into()
            .unwrap();
        // TODO: should this be a config option?
        let fee_tier = FeeTier::default();

        // use the transaction builder in the custody service to construct a transaction, including
        // each tracked message as an IbcRelay message
        let mut planner = Planner::new(OsRng);

        planner.set_gas_prices(gas_prices).set_fee_tier(fee_tier);

        let return_address = self
            .config
            .kms_config
            .spend_key
            .full_viewing_key()
            .payment_address(0.into())
            .0;

        let tx_memo = "IBC Relay".to_string();

        let memo_plaintext = MemoPlaintext::new(return_address, tx_memo.clone()).unwrap();

        for msg in tracked_msgs.msgs {
            let raw_ibcrelay_msg = ProtoIbcRelay {
                raw_action: Some(pbjson_types::Any {
                    type_url: msg.type_url.clone(),
                    value: msg.value.clone().into(),
                }),
            };
            let ibc_action =
                IbcRelay::try_from(raw_ibcrelay_msg).expect("failed to convert to IbcRelay");
            planner.ibc_action(ibc_action);
        }

        let plan = planner
            .memo(memo_plaintext)
            .unwrap()
            .plan(&mut self.view_client, AddressIndex::new(0))
            .await
            .context("can't build send transaction")
            .map_err(|e| Error::temp_penumbra_error(e.to_string()))?;

        let tx = penumbra_wallet::build_transaction(
            &self.config.kms_config.spend_key.full_viewing_key(),
            &mut self.view_client,
            &mut self.custody_client,
            plan,
        )
        .await
        .map_err(|e| Error::temp_penumbra_error(e.to_string()))?;

        let gas_cost = tx.gas_cost();
        let fee = gas_prices.fee(&gas_cost);

        assert!(
            tx.transaction_parameters().fee.amount() >= fee,
            "paid fee {} must be greater than minimum fee {}",
            tx.transaction_parameters().fee.amount(),
            fee
        );

        let txid = self.submit_transaction(tx).await.map_err(|e| {
            tracing::error!("error submitting transaction: {}", e);
            Error::temp_penumbra_error(e.to_string())
        })?;

        // query the tendermint rpc for the transaction's events
        let tm_tx_hash: tendermint::Hash = txid.0.to_vec().try_into().unwrap();
        let tm_tx = self
            .tendermint_rpc_client
            .tx(tm_tx_hash, false)
            .await
            .map_err(|e| {
                tracing::error!("error querying transaction: {}", e);
                Error::temp_penumbra_error(e.to_string())
            })?;

        let height = ICSHeight::new(self.config.id.version(), u64::from(tm_tx.height)).unwrap();
        let events = tm_tx
            .tx_result
            .events
            .iter()
            .map(|ev| IbcEventWithHeight::new(ibc_event_try_from_abci_event(ev).unwrap(), height))
            .collect();

        Ok(events)
    }

    /// Submits a transaction to the network.
    async fn submit_transaction(
        &mut self,
        transaction: penumbra_transaction::Transaction,
    ) -> anyhow::Result<penumbra_transaction::txhash::TransactionId> {
        println!("broadcasting transaction and awaiting confirmation...");
        let mut rsp =
            ViewClient::broadcast_transaction(&mut self.view_client, transaction, true).await?;

        let id = (async move {
            while let Some(rsp) = rsp.try_next().await? {
                match rsp.status {
                    Some(status) => match status {
                        BroadcastStatus::BroadcastSuccess(bs) => {
                            println!(
                                "transaction broadcast successfully: {}",
                                penumbra_transaction::txhash::TransactionId::try_from(
                                    bs.id.expect("detected transaction missing id")
                                )?
                            );
                        }
                        BroadcastStatus::Confirmed(c) => {
                            let id = c.id.expect("detected transaction missing id").try_into()?;
                            if c.detection_height != 0 {
                                println!(
                                    "transaction confirmed and detected: {} @ height {}",
                                    id, c.detection_height
                                );
                            } else {
                                println!("transaction confirmed and detected: {}", id);
                            }
                            return Ok(id);
                        }
                    },
                    None => {
                        // No status is unexpected behavior
                        return Err(anyhow::anyhow!(
                            "empty BroadcastTransactionResponse message"
                        ));
                    }
                }
            }

            Err(anyhow::anyhow!(
                "should have received BroadcastTransaction status or error"
            ))
        }
        .boxed())
        .await
        .context("error broadcasting transaction")?;

        Ok(id)
    }
}

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

        let rpc_client = HttpClient::new(config.rpc_addr.clone())
            .map_err(|e| Error::rpc(config.rpc_addr.clone(), e))?;

        let node_info = rt.block_on(fetch_node_info(&rpc_client, &config))?;

        let fvk = config.kms_config.spend_key.full_viewing_key();

        // TODO: pass None until we figure out where to persist view data
        let svc = rt
            .block_on(ViewServer::load_or_initialize(
                None::<&str>,
                fvk,
                config.grpc_addr.clone().into(),
            ))
            .map_err(|e| Error::temp_penumbra_error(e.to_string()))?;

        let svc = ViewServiceServer::new(svc);
        let mut view_client = ViewServiceClient::new(box_grpc_svc::local(svc));

        let soft_kms = penumbra_custody::soft_kms::SoftKms::new(config.kms_config.clone());
        let custody_svc = CustodyServiceServer::new(soft_kms);
        let custody_client = CustodyServiceClient::new(box_grpc_svc::local(custody_svc));

        tracing::info!("starting view service sync");

        let sync_height = rt
            .block_on(async {
                let mut stream = ViewClient::status_stream(&mut view_client).await?;
                let mut sync_height = 0u64;
                while let Some(status) = stream.next().await.transpose()? {
                    sync_height = status.full_sync_height;
                }
                Ok(sync_height)
            })
            .map_err(|e: anyhow::Error| Error::temp_penumbra_error(e.to_string()))?;

        tracing::info!(?sync_height, "view service sync complete");

        let grpc_addr = Uri::from_str(&config.grpc_addr.to_string())
            .map_err(|e| Error::invalid_uri(config.grpc_addr.to_string(), e))?;

        let ibc_client_grpc_client = rt
            .block_on(IbcClientQueryClient::connect(grpc_addr.clone()))
            .map_err(Error::grpc_transport)?;
        let ibc_connection_grpc_client = rt
            .block_on(IbcConnectionQueryClient::connect(grpc_addr.clone()))
            .map_err(Error::grpc_transport)?;
        let ibc_channel_grpc_client = rt
            .block_on(IbcChannelQueryClient::connect(grpc_addr.clone()))
            .map_err(Error::grpc_transport)?;

        let tendermint_light_client = TmLightClient::from_rpc_parameters(
            config.id.clone(),
            config.rpc_addr.clone(),
            config.rpc_timeout.clone(),
            node_info.id,
            true,
        )?;

        tracing::info!("ibc grpc query clients connected");

        Ok(Self {
            config,
            rt,
            view_client: view_client.clone(),
            custody_client,
            tendermint_rpc_client: rpc_client,
            tendermint_light_client,
            tx_monitor_cmd: None,

            ibc_client_grpc_client,
            ibc_connection_grpc_client,
            ibc_channel_grpc_client,
        })
    }

    fn shutdown(self) -> Result<(), Error> {
        todo!()
    }

    fn health_check(&mut self) -> Result<HealthCheck, Error> {
        let catching_up = self
            .rt
            .block_on(async {
                let status = ViewClient::status(&mut self.view_client).await?;
                Ok(status.catching_up)
            })
            .map_err(|e: anyhow::Error| Error::temp_penumbra_error(e.to_string()))?;

        if catching_up {
            Ok(HealthCheck::Unhealthy(Box::new(
                Error::temp_penumbra_error(
                    anyhow::anyhow!("view service is not synced").to_string(),
                ),
            )))
        } else {
            Ok(HealthCheck::Healthy)
        }
    }

    fn subscribe(&mut self) -> Result<Subscription, Error> {
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
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        let runtime = self.rt.clone();
        let msg_len = tracked_msgs.msgs.len();
        let events = runtime.block_on(self.broadcast_messages(tracked_msgs))?;

        Ok(events)
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<tendermint_rpc::endpoint::broadcast::tx_sync::Response>, Error> {
        todo!()
    }

    fn verify_header(
        &mut self,
        trusted: ibc_relayer_types::Height,
        target: ibc_relayer_types::Height,
        client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        todo!()
    }

    fn check_misbehaviour(
        &mut self,
        update: &ibc_relayer_types::core::ics02_client::events::UpdateClient,
        client_state: &AnyClientState,
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
        // This is hardcoded for now.
        Ok(b"ibc-data".to_vec().try_into().unwrap())
    }

    fn query_application_status(&self) -> Result<crate::chain::endpoint::ChainStatus, Error> {
        todo!()
    }

    fn query_clients(
        &self,
        request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        crate::time!(
            "query_clients",
            {
                "src_chain": self.config().id().to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_clients");

        let mut client = self.ibc_client_grpc_client.clone();

        let request = tonic::Request::new(request.into());
        let response = self
            .rt
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
                        tracing::warn!(
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
        request: QueryClientStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        let mut client = self.ibc_client_grpc_client.clone();

        let mut req = ibc_proto::ibc::core::client::v1::QueryClientStateRequest {
            client_id: request.client_id.to_string(),
            // NOTE: height is ignored
        }
        .into_request();

        let map = req.metadata_mut();
        let height_str: String = match request.height {
            QueryHeight::Latest => 0.to_string(),
            QueryHeight::Specific(h) => h.to_string(),
        };
        map.insert("height", height_str.parse().expect("valid ascii string"));

        let response = self
            .rt
            .block_on(client.client_state(req))
            .map_err(|e| Error::grpc_status(e, "query_client_state".to_owned()))?
            .into_inner();

        let Some(client_state) = response.client_state else {
            return Err(Error::empty_response_value());
        };

        let client_state: AnyClientState = client_state
            .try_into()
            .map_err(|_| Error::temp_penumbra_error("couldnt decode AnyClientState".to_string()))?;

        match include_proof {
            IncludeProof::Yes => Ok((client_state, Some(decode_merkle_proof(response.proof)?))),
            IncludeProof::No => Ok((client_state, None)),
        }
    }

    fn query_consensus_state(
        &self,
        request: QueryConsensusStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyConsensusState, Option<MerkleProof>), Error> {
        let mut client = self.ibc_client_grpc_client.clone();

        let mut req = ibc_proto::ibc::core::client::v1::QueryConsensusStateRequest {
            client_id: request.client_id.to_string(),
            revision_height: request.consensus_height.revision_height(),
            revision_number: request.consensus_height.revision_number(),
            latest_height: false, // TODO?
        }
        .into_request();

        let map = req.metadata_mut();
        let height_str: String = match request.query_height {
            QueryHeight::Latest => 0.to_string(),
            QueryHeight::Specific(h) => h.to_string(),
        };
        map.insert("height", height_str.parse().expect("valid ascii string"));

        let response = self
            .rt
            .block_on(client.consensus_state(req))
            .map_err(|e| Error::grpc_status(e, "query_consensus_state".to_owned()))?
            .into_inner();

        let Some(consensus_state) = response.consensus_state else {
            return Err(Error::empty_response_value());
        };

        let consensus_state: AnyConsensusState = consensus_state.try_into().map_err(|_| {
            Error::temp_penumbra_error("couldnt decode AnyConsensusState".to_string())
        })?;

        if !matches!(consensus_state, AnyConsensusState::Tendermint(_)) {
            return Err(Error::consensus_state_type_mismatch(
                ClientType::Tendermint,
                consensus_state.client_type(),
            ));
        }

        match include_proof {
            IncludeProof::Yes => Ok((consensus_state, Some(decode_merkle_proof(response.proof)?))),
            IncludeProof::No => Ok((consensus_state, None)),
        }
    }

    fn query_consensus_state_heights(
        &self,
        request: QueryConsensusStateHeightsRequest,
    ) -> Result<Vec<ibc_relayer_types::Height>, Error> {
        let mut client = self.ibc_client_grpc_client.clone();

        let req = ibc_proto::ibc::core::client::v1::QueryConsensusStateHeightsRequest {
            client_id: request.client_id.to_string(),
            pagination: Default::default(),
        };

        let response = self
            .rt
            .block_on(client.consensus_state_heights(req))
            .map_err(|e| Error::grpc_status(e, "query_consensus_state_heights".to_owned()))?
            .into_inner();

        let heights = response
            .consensus_state_heights
            .into_iter()
            .filter_map(|h| ICSHeight::new(h.revision_number, h.revision_height).ok())
            .collect();
        Ok(heights)
    }

    fn query_upgraded_client_state(
        &self,
        _request: QueryUpgradedClientStateRequest,
    ) -> Result<(AnyClientState, MerkleProof), Error> {
        todo!()
    }

    fn query_upgraded_consensus_state(
        &self,
        _request: QueryUpgradedConsensusStateRequest,
    ) -> Result<(AnyConsensusState, MerkleProof), Error> {
        todo!()
    }

    fn query_connections(
        &self,
        request: QueryConnectionsRequest,
    ) -> Result<Vec<IdentifiedConnectionEnd>, Error> {
        crate::time!(
            "query_connections",
            {
                "src_chain": self.config().id().to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_connections");

        let mut client = self.ibc_connection_grpc_client.clone();

        let request = tonic::Request::new(request.into());

        let response = self
            .rt
            .block_on(client.connections(request))
            .map_err(|e| Error::grpc_status(e, "query_connections".to_owned()))?
            .into_inner();

        let connections = response
            .connections
            .into_iter()
            .filter_map(|co| {
                IdentifiedConnectionEnd::try_from(co.clone())
                    .map_err(|e| {
                        tracing::warn!(
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
        request: QueryClientConnectionsRequest,
    ) -> Result<Vec<ibc_relayer_types::core::ics24_host::identifier::ConnectionId>, Error> {
        crate::time!(
            "query_client_connections",
            {
                "src_chain": self.config().id().to_string(),
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
        request: QueryConnectionRequest,
        include_proof: IncludeProof,
    ) -> Result<(ConnectionEnd, Option<MerkleProof>), Error> {
        let mut client = self.ibc_connection_grpc_client.clone();
        let mut req = ibc_proto::ibc::core::connection::v1::QueryConnectionRequest {
            connection_id: request.connection_id.to_string(),
            // TODO height is ignored
        }
        .into_request();

        let map = req.metadata_mut();
        let height_str: String = match request.height {
            QueryHeight::Latest => 0.to_string(),
            QueryHeight::Specific(h) => h.to_string(),
        };
        map.insert("height", height_str.parse().expect("valid ascii string"));

        let response = self.rt.block_on(client.connection(req)).map_err(|e| {
            if e.code() == tonic::Code::NotFound {
                Error::connection_not_found(request.connection_id.clone())
            } else {
                Error::grpc_status(e, "query_connection".to_owned())
            }
        })?;

        let resp = response.into_inner();
        let connection_end: ConnectionEnd = match resp.connection {
            Some(raw_connection) => raw_connection.try_into().map_err(Error::ics03)?,
            None => {
                // When no connection is found, the GRPC call itself should return
                // the NotFound error code. Nevertheless even if the call is successful,
                // the connection field may not be present, because in protobuf3
                // everything is optional.
                return Err(Error::connection_not_found(request.connection_id.clone()));
            }
        };

        match include_proof {
            IncludeProof::Yes => Ok((connection_end, Some(decode_merkle_proof(resp.proof)?))),
            IncludeProof::No => Ok((connection_end, None)),
        }
    }

    fn query_connection_channels(
        &self,
        request: QueryConnectionChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let request = tonic::Request::new(request.into());

        let response = self
            .rt
            .block_on(client.connection_channels(request))
            .map_err(|e| Error::grpc_status(e, "query_connection_channels".to_owned()))?
            .into_inner();

        let channels = response
            .channels
            .into_iter()
            .filter_map(|ch| {
                IdentifiedChannelEnd::try_from(ch.clone())
                    .map_err(|e| {
                        tracing::warn!(
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
        request: QueryChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let request = tonic::Request::new(request.into());

        let response = self
            .rt
            .block_on(client.channels(request))
            .map_err(|e| Error::grpc_status(e, "query_channels".to_owned()))?
            .into_inner();

        let channels = response
            .channels
            .into_iter()
            .filter_map(|ch| {
                IdentifiedChannelEnd::try_from(ch.clone())
                    .map_err(|e| {
                        tracing::warn!(
                            "channel with ID {} failed parsing. Error: {}",
                            PrettyIdentifiedChannel(&ch),
                            e
                        );
                    })
                    .ok()
            })
            .collect();

        Ok(channels)
    }

    fn query_channel(
        &self,
        request: QueryChannelRequest,
        include_proof: IncludeProof,
    ) -> Result<(ChannelEnd, Option<MerkleProof>), Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let req = ibc_proto::ibc::core::channel::v1::QueryChannelRequest {
            port_id: request.port_id.to_string(),
            channel_id: request.channel_id.to_string(),
        };

        let request = tonic::Request::new(req);
        let response = self
            .rt
            .block_on(client.channel(request))
            .map_err(|e| Error::grpc_status(e, "query_channel".to_owned()))?
            .into_inner();

        let Some(channel_end) = response.channel else {
            return Err(Error::empty_response_value());
        };

        let channel_end: ChannelEnd = channel_end
            .try_into()
            .map_err(|e| Error::temp_penumbra_error("couldnt decode ChannelEnd".to_string()))?;

        match include_proof {
            IncludeProof::Yes => Ok((channel_end, Some(decode_merkle_proof(response.proof)?))),
            IncludeProof::No => Ok((channel_end, None)),
        }
    }

    fn query_channel_client_state(
        &self,
        request: QueryChannelClientStateRequest,
    ) -> Result<Option<IdentifiedAnyClientState>, Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let request = tonic::Request::new(request.into());

        let response = self
            .rt
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
        request: QueryPacketCommitmentRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let req = ibc_proto::ibc::core::channel::v1::QueryPacketCommitmentRequest {
            port_id: request.port_id.to_string(),
            channel_id: request.channel_id.to_string(),
            sequence: request.sequence.into(),
        };

        let request = tonic::Request::new(req);
        let response = self
            .rt
            .block_on(client.packet_commitment(request))
            .map_err(|e| Error::grpc_status(e, "query_packet_commitment".to_owned()))?
            .into_inner();

        match include_proof {
            IncludeProof::Yes => Ok((
                response.commitment,
                Some(decode_merkle_proof(response.proof)?),
            )),
            IncludeProof::No => Ok((response.commitment, None)),
        }
    }

    fn query_packet_commitments(
        &self,
        request: QueryPacketCommitmentsRequest,
    ) -> Result<(Vec<Sequence>, ibc_relayer_types::Height), Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let request = tonic::Request::new(request.into());

        let response = self
            .rt
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
        request: QueryPacketReceiptRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let req = ibc_proto::ibc::core::channel::v1::QueryPacketReceiptRequest {
            port_id: request.port_id.to_string(),
            channel_id: request.channel_id.to_string(),
            sequence: request.sequence.into(),
            // NOTE: height is ignored
        };

        let request = tonic::Request::new(req);
        let response = self
            .rt
            .block_on(client.packet_receipt(request))
            .map_err(|e| Error::grpc_status(e, "query_packet_receipt".to_owned()))?
            .into_inner();

        // TODO: is this right?
        let value = match response.received {
            true => vec![1],
            false => vec![0],
        };

        match include_proof {
            IncludeProof::Yes => Ok((value, Some(decode_merkle_proof(response.proof)?))),
            IncludeProof::No => Ok((value, None)),
        }
    }

    fn query_unreceived_packets(
        &self,
        request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        let mut client = self.ibc_channel_grpc_client.clone();

        let request = tonic::Request::new(request.into());

        let mut response = self
            .rt
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
        request: QueryPacketAcknowledgementRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let req = ibc_proto::ibc::core::channel::v1::QueryPacketAcknowledgementRequest {
            port_id: request.port_id.to_string(),
            channel_id: request.channel_id.to_string(),
            sequence: request.sequence.into(),
            // NOTE: height is ignored
        };

        let request = tonic::Request::new(req);
        let response = self
            .rt
            .block_on(client.packet_acknowledgement(request))
            .map_err(|e| Error::grpc_status(e, "query_packet_acknowledgement".to_owned()))?
            .into_inner();

        match include_proof {
            IncludeProof::Yes => Ok((
                response.acknowledgement,
                Some(decode_merkle_proof(response.proof)?),
            )),
            IncludeProof::No => Ok((response.acknowledgement, None)),
        }
    }

    fn query_packet_acknowledgements(
        &self,
        request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, ibc_relayer_types::Height), Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let request = tonic::Request::new(request.into());

        let response = self
            .rt
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
        request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let request = tonic::Request::new(request.into());

        let mut response = self
            .rt
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
        request: QueryNextSequenceReceiveRequest,
        include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        let mut client = self.ibc_channel_grpc_client.clone();
        let request = tonic::Request::new(request.into());

        let response = self
            .rt
            .block_on(client.next_sequence_receive(request))
            .map_err(|e| Error::grpc_status(e, "query_next_sequence_receive".to_owned()))?
            .into_inner();

        match include_proof {
            IncludeProof::Yes => Ok((
                response.next_sequence_receive.into(),
                Some(decode_merkle_proof(response.proof)?),
            )),
            IncludeProof::No => Ok((response.next_sequence_receive.into(), None)),
        }
    }

    fn query_txs(&self, request: QueryTxRequest) -> Result<Vec<IbcEventWithHeight>, Error> {
        use crate::chain::cosmos::query::tx::query_txs;

        self.rt.block_on(query_txs(
            self.id(),
            &self.tendermint_rpc_client,
            &self.config.rpc_addr,
            request,
        ))
    }

    fn query_packet_events(
        &self,
        mut request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        use crate::chain::cosmos::{
            query::tx::{query_packets_from_block, query_packets_from_txs},
            sort_events_by_sequence,
        };

        match request.height {
            // Usage note: `Qualified::Equal` is currently only used in the call hierarchy involving
            // the CLI methods, namely the CLI for `tx packet-recv` and `tx packet-ack` when the
            // user passes the flag `packet-data-query-height`.
            Qualified::Equal(_) => self.rt.block_on(query_packets_from_block(
                self.id(),
                &self.tendermint_rpc_client,
                &self.config.rpc_addr,
                &request,
            )),
            Qualified::SmallerEqual(_) => {
                let tx_events = self.rt.block_on(query_packets_from_txs(
                    self.id(),
                    &self.tendermint_rpc_client,
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
                    self.rt.block_on(self.query_packets_from_blocks(&request))?
                } else {
                    Default::default()
                };

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
        _request: QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        todo!()
    }

    fn build_client_state(
        &self,
        height: ibc_relayer_types::Height,
        settings: ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        use ibc_relayer_types::clients::ics07_tendermint::client_state::AllowUpdate;
        let ClientSettings::Tendermint(settings) = settings;

        // two hour duration
        // TODO what is this?
        let two_hours = Duration::from_secs(2 * 60 * 60);
        let unbonding_period = two_hours;
        let trusting_period_default = 2 * unbonding_period / 3;
        let trusting_period = settings.trusting_period.unwrap_or(trusting_period_default);

        let proof_specs = IBC_PROOF_SPECS.clone();

        Self::ClientState::new(
            self.id().clone(),
            settings.trust_threshold,
            trusting_period,
            unbonding_period,
            settings.max_clock_drift,
            height,
            proof_specs.into(),
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
    ) -> Result<Self::ConsensusState, Error> {
        Ok(Self::ConsensusState::from(light_block.signed_header.header))
    }

    fn build_header(
        &mut self,
        trusted_height: ibc_relayer_types::Height,
        target_height: ibc_relayer_types::Height,
        client_state: &AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        use crate::light_client::Verified;

        let now = self.chain_status()?.sync_info.latest_block_time;

        todo!()

        // Get the light block at target_height from chain.
        /*
        let Verified { target, supporting } = self.light_client.header_and_minimal_set(
            trusted_height,
            target_height,
            client_state,
            now,
        )?;

        Ok((target, supporting))*/
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
        requests: Vec<CrossChainQueryRequest>,
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
            ClientId,
        )>,
        Error,
    > {
        todo!()
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

fn decode_merkle_proof(proof_bytes: Vec<u8>) -> Result<MerkleProof, Error> {
    let proof_bytes = CommitmentProofBytes::try_from(proof_bytes).map_err(|e| {
        Error::temp_penumbra_error(format!("couldnt decode CommitmentProofBytes: {}", e))
    })?;
    let raw_proof: RawMerkleProof = RawMerkleProof::try_from(proof_bytes)
        .map_err(|e| Error::temp_penumbra_error(format!("couldnt decode RawMerkleProof: {}", e)))?;

    let proof = MerkleProof::from(raw_proof);

    Ok(proof)
}

const LEAF_DOMAIN_SEPARATOR: &[u8] = b"JMT::LeafNode";
const INTERNAL_DOMAIN_SEPARATOR: &[u8] = b"JMT::IntrnalNode";

const SPARSE_MERKLE_PLACEHOLDER_HASH: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";

fn ics23_spec() -> ics23::ProofSpec {
    ics23::ProofSpec {
        leaf_spec: Some(ics23::LeafOp {
            hash: ics23::HashOp::Sha256.into(),
            prehash_key: ics23::HashOp::Sha256.into(),
            prehash_value: ics23::HashOp::Sha256.into(),
            length: ics23::LengthOp::NoPrefix.into(),
            prefix: LEAF_DOMAIN_SEPARATOR.to_vec(),
        }),
        inner_spec: Some(ics23::InnerSpec {
            hash: ics23::HashOp::Sha256.into(),
            child_order: vec![0, 1],
            min_prefix_length: INTERNAL_DOMAIN_SEPARATOR.len() as i32,
            max_prefix_length: INTERNAL_DOMAIN_SEPARATOR.len() as i32,
            child_size: 32,
            empty_child: SPARSE_MERKLE_PLACEHOLDER_HASH.to_vec(),
        }),
        min_depth: 0,
        max_depth: 64,
        prehash_key_before_comparison: true,
    }
}
/// The ICS23 proof spec for penumbra's IBC state; this can be used to verify proofs
/// for other substores in the penumbra state, provided that the data is indeed inside a substore
/// (as opposed to directly in the root store.)
pub static IBC_PROOF_SPECS: Lazy<Vec<ics23::ProofSpec>> =
    Lazy::new(|| vec![ics23_spec(), ics23_spec()]);

async fn fetch_node_info(
    rpc_client: &HttpClient,
    config: &PenumbraConfig,
) -> Result<tendermint::node::Info, Error> {
    crate::time!("fetch_node_info",
    {
        "src_chain": config.id.to_string(),
    });

    rpc_client
        .status()
        .await
        .map(|s| s.node_info)
        .map_err(|e| Error::rpc(config.rpc_addr.clone(), e))
}
