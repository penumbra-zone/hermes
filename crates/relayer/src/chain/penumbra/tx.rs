use super::PenumbraChain;
use crate::{
    chain::{
        cosmos::{types::tx::TxStatus, types::tx::TxSyncResult, wait::wait_for_block_commits},
        endpoint::ChainEndpoint,
        tracking::TrackedMsgs,
    },
    error::Error,
    event::IbcEventWithHeight,
};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use penumbra_proto::core::ibc::v1alpha1::IbcAction;
use prost::Message;
use tendermint_rpc::{endpoint::broadcast::tx_sync::Response, Client};
use tracing::instrument;

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

impl PenumbraChain {
    #[instrument(
                name = "send_messages_and_wait_check_tx",
                level = "error",
                skip_all,
                fields(
                    chain = %self.id(),
                    tracking_id = %tracked_msgs.tracking_id()
                ),
            )]
    pub(super) async fn do_send_messages_and_wait_check_tx(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<tendermint_rpc::endpoint::broadcast::tx_sync::Response>, Error> {
        crate::time!(
            "send_messages_and_wait_check_tx",
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

        Ok(vec![res])
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
    pub(super) async fn do_send_messages_and_wait_commit(
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
