#include "bls_aggregator.h"

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("bls_aggregator");

BLSAggregator::BLSAggregator(service_nodes::service_node_list& _snl, std::shared_ptr<oxenmq::OxenMQ> _omq, std::shared_ptr<BLSSigner> _bls_signer)
    : service_node_list(_snl), omq(std::move(_omq)), bls_signer(std::move(_bls_signer)) {
}

BLSAggregator::~BLSAggregator() {
}

std::string BLSAggregator::aggregatePubkeyHex() {
    //bls::PublicKey aggregate_pubkey; 
    //aggregate_pubkey.clear();
    //for(auto& node : nodes) {
        //aggregate_pubkey.add(node.getPublicKey());
    //}
    //return bls_utils::PublicKeyToHex(aggregate_pubkey);
    return "";
}

std::vector<std::string> BLSAggregator::getPubkeys() {
    std::vector<std::string> pubkeys;
    std::mutex pubkeys_mutex;

    processNodes(
        "bls.pubkey_request",
        [this, &pubkeys, &pubkeys_mutex](bool success, std::vector<std::string> data) {
            if (success) {
                std::lock_guard<std::mutex> lock(pubkeys_mutex);
                pubkeys.emplace_back(data[0]);
            }
        },
        [](){}
    );

    return pubkeys;
}

aggregateResponse BLSAggregator::aggregateSignatures(const std::string& message) {
    const std::array<unsigned char, 32> hash = BLSSigner::hash(message);
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<int64_t> signers;
    std::mutex signers_mutex;
    int64_t signers_index = 0;

    processNodes(
        "bls.signature_request",
        [this, &aggSig, &signers, &signers_mutex, &signers_index](bool success, std::vector<std::string> data) {
            if (success) {
                bls::Signature external_signature;
                external_signature.setStr(data[0]);
                std::lock_guard<std::mutex> lock(signers_mutex);
                aggSig.add(external_signature);
                signers.push_back(signers_index);
            }
            signers_index++;
        },
        [this, &aggSig, &hash] {
            const auto my_signature = bls_signer->signHash(hash);
            aggSig.add(my_signature);
        },
        message
    );

    const auto non_signers = findNonSigners(signers);
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateResponse{non_signers, sig_str};
}

aggregateMerkleResponse BLSAggregator::aggregateMerkleRewards(const std::string& our_merkle_root) {
    const std::array<unsigned char, 32> hash = BLSSigner::hash(our_merkle_root);
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<int64_t> signers;
    std::mutex signers_mutex;
    int64_t signers_index = 0;

    processNodes(
        "bls.rewards_merkle",
        [this, &aggSig, &signers, &signers_mutex, &our_merkle_root, &signers_index](bool success, std::vector<std::string> data) {
            if (success && data[0] == our_merkle_root) {
                bls::Signature external_signature;
                external_signature.setStr(data[1]);
                std::lock_guard<std::mutex> lock(signers_mutex);
                aggSig.add(external_signature);
                signers.push_back(signers_index);
            }
            signers_index++;
        },
        [this, &aggSig, &hash] {
            const auto my_signature = bls_signer->signHash(hash);
            aggSig.add(my_signature);
        }
    );

    const auto non_signers = findNonSigners(signers);
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateMerkleResponse{our_merkle_root, non_signers, sig_str};
}



std::vector<int64_t> BLSAggregator::findNonSigners(const std::vector<int64_t>& indices) {
    std::vector<int64_t> nonSignerIndices = {};
    for (int64_t i = 0; i < static_cast<int64_t>(service_node_list.get_service_node_count()); ++i) {
        if (std::find(indices.begin(), indices.end(), i) == indices.end()) {
            nonSignerIndices.push_back(i);
        }
    }
    return nonSignerIndices;
}
