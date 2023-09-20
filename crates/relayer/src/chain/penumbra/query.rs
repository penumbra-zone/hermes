use crate::chain::cosmos::query::tx::filter_matching_event;
use crate::chain::endpoint::ChainEndpoint;
use crate::chain::requests::QueryHeight;
use crate::event::IbcEventWithHeight;
use crate::{chain::requests::QueryPacketEventDataRequest, error::Error};
use ibc_relayer_types::core::{
    ics04_channel::packet::Sequence, ics23_commitment::merkle::convert_tm_to_ics_merkle_proof,
};
use ibc_relayer_types::Height as ICSHeight;
use tendermint::block::Height;
use tendermint_rpc::{Client, HttpClient, Order, Url};

use crate::chain::cosmos::query::{packet_query, QueryResponse};

use super::PenumbraChain;

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

impl PenumbraChain {
    pub(super) fn query_packet_from_block(
        &self,
        request: &QueryPacketEventDataRequest,
        seqs: &[Sequence],
        block_height: &ICSHeight,
    ) -> Result<(Vec<IbcEventWithHeight>, Vec<IbcEventWithHeight>), Error> {
        crate::time!(
            "query_block: query block packet events",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_block");

        let mut begin_block_events = vec![];
        let mut end_block_events = vec![];

        let tm_height =
            tendermint::block::Height::try_from(block_height.revision_height()).unwrap();

        let response = self
            .block_on(self.rpc_client.block_results(tm_height))
            .map_err(|e| Error::rpc(self.config().rpc_addr.clone(), e))?;

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

    pub(super) fn query_packets_from_blocks(
        &self,
        request: &QueryPacketEventDataRequest,
    ) -> Result<(Vec<IbcEventWithHeight>, Vec<IbcEventWithHeight>), Error> {
        crate::time!(
            "query_blocks: query block packet events",
            {
                "src_chain": self.config().id.to_string(),
            }
        );
        crate::telemetry!(query, self.id(), "query_blocks");

        let mut begin_block_events = vec![];
        let mut end_block_events = vec![];

        for seq in request.sequences.iter().copied() {
            let response = self
                .block_on(self.rpc_client.block_search(
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
                    Order::Descending,
                ))
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
    pub(super) async fn get_anchor(
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

        Ok(penumbra_proto::core::crypto::v1alpha1::MerkleRoot {
            inner: res.value[2..].into(),
        })
    }
}
