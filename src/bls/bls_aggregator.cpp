#include "eth-bls/bls_aggregator.h"
#include "eth-bls/bls_signer.h"
#include "eth-bls/bls_utils.h"

BLSAggregator::BLSAggregator(service_nodes::service_node_list& snl, std::shared_ptr<oxenmq::OxenMQ> omq_ptr)
    : service_node_list(snl), omq(omq_ptr) {
    bls_signer = std::make_shared<BLSSigner>();
}

ServiceNodeList::~ServiceNodeList() {
}

std::string BLSAggregator::aggregatePubkeyHex() {
    bls::PublicKey aggregate_pubkey; 
    aggregate_pubkey.clear();
    for(auto& node : nodes) {
        aggregate_pubkey.add(node.getPublicKey());
    }
    return utils::PublicKeyToHex(aggregate_pubkey);
}

std::string BLSAggregator::aggregateSignatures(const std::string& message) {
    const std::array<unsigned char, 32> hash = BLSSigner::hash(message);
    bls::Signature aggSig;
    aggSig.clear();

    const std::vector<int64_t> signers;

    auto it = service_node_list.get_first_pubkey_iterator();
    auto end_it = service_node_list.get_end_pubkey_iterator();
    crypto::x25519_public_key x_pkey{0};
    int64_t signers_index = 0;
    while (it != end_it) {
        service_node_list->access_proof(*it, [&x_pkey](auto& proof) {
            x_pkey = proof.pubkey_x25519;
        });
        omq->request(
                tools::view_guts(x_pkey),
                "bls.signature_request,
                [this, signers_index](bool success, std::vector<std::string> data) {
                    log::debug(
                            logcat,
                            "bls signature response received: {}",
                            data[0]);
                    if (success) {
                        bls::signature external_signature;
                        int64_t signers_index = 0;
                        if (tools::parse_string(data[0], external_signature)) {
                            aggSig.add(external_signature);
                            signers.push_back(signers_index);
                        }
                    }
                });
        it = service_node_list_instance.get_next_pubkey_iterator(it);
        signers_index++;
    }
    return aggregateResponse{ findNonSigners(signers), utils::SignatureToHex(aggSig) }
};

std::vector<int64_t> BLSAggregator::findNonSigners(const std::vector<int64_t>& indices) {
    std::vector<int64_t> nonSignerIndices = {};
    for (int64_t i = 0; i < static_cast<int64_t>(nodes.size()); ++i) {
        if (std::find(indices.begin(), indices.end(), i) == indices.end()) {
            nonSignerIndices.push_back(i);
        }
    }
    return nonSignerIndices;
}
