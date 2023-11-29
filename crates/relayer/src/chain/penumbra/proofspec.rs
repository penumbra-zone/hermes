use ibc_relayer_types::core::ics23_commitment::specs::ProofSpecs;

const SPARSE_MERKLE_PLACEHOLDER_HASH: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";

fn jmt_spec_no_prehash() -> ics23::ProofSpec {
    ics23::ProofSpec {
        leaf_spec: Some(ics23::LeafOp {
            hash: ics23::HashOp::Sha256.into(),
            prehash_key: ics23::HashOp::Sha256.into(),
            prehash_value: ics23::HashOp::Sha256.into(),
            length: ics23::LengthOp::NoPrefix.into(),
            prefix: jmt::proof::LEAF_DOMAIN_SEPARATOR.to_vec(),
        }),
        inner_spec: Some(ics23::InnerSpec {
            hash: ics23::HashOp::Sha256.into(),
            child_order: vec![0, 1],
            min_prefix_length: jmt::proof::INTERNAL_DOMAIN_SEPARATOR.len() as i32,
            max_prefix_length: jmt::proof::INTERNAL_DOMAIN_SEPARATOR.len() as i32,
            child_size: 32,
            empty_child: SPARSE_MERKLE_PLACEHOLDER_HASH.to_vec(),
        }),
        min_depth: 0,
        max_depth: 64,
        prehash_key_before_comparison: false, // for now, until support lands
    }
}

fn jmt_spec_with_prehash() -> ics23::ProofSpec {
    let mut spec = jmt_spec_no_prehash();
    spec.prehash_key_before_comparison = true;
    spec
}

// TODO: this should re-export the proof specs from the Penumbra crate
pub fn penumbra_proof_spec_no_prehash() -> ProofSpecs {
    vec![jmt_spec_no_prehash(), jmt_spec_no_prehash()].into()
}

pub fn penumbra_proof_spec_with_prehash() -> ProofSpecs {
    vec![jmt_spec_with_prehash(), jmt_spec_with_prehash()].into()
}
