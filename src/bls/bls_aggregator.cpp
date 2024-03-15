#include "bls_aggregator.h"

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("bls_aggregator");

BLSAggregator::BLSAggregator(service_nodes::service_node_list& _snl, std::shared_ptr<oxenmq::OxenMQ> _omq, std::shared_ptr<BLSSigner> _bls_signer)
    : service_node_list(_snl), omq(std::move(_omq)), bls_signer(std::move(_bls_signer)) {
}

BLSAggregator::~BLSAggregator() {
}

std::vector<std::pair<std::string, std::string>> BLSAggregator::getPubkeys() {
    std::vector<std::pair<std::string, std::string>> pubkeys;
    std::mutex pubkeys_mutex;

    processNodes(
        "bls.pubkey_request",
        [this, &pubkeys, &pubkeys_mutex](bool success, std::vector<std::string> data) {
            if (success) {
                std::lock_guard<std::mutex> lock(pubkeys_mutex);
                pubkeys.emplace_back(data[0], data[1]);
            }
        },
        [](){}
    );

    return pubkeys;
}

blsRegistrationResponse BLSAggregator::registration() const {
    return blsRegistrationResponse{bls_signer->getPublicKeyHex(), bls_signer->proofOfPossession(), "","",""};
}

aggregateWithdrawalResponse BLSAggregator::aggregateRewards(const std::string& address) {
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    uint64_t amount = 0;
    uint64_t height = 0;
    std::string signed_message = "";
    bool initial_data_set = false;
    std::string lower_eth_address = address;
    if (lower_eth_address.substr(0, 2) != "0x") {
        lower_eth_address = "0x" + lower_eth_address;
    }
    std::transform(lower_eth_address.begin(), lower_eth_address.end(), lower_eth_address.begin(),
        [](unsigned char c){ return std::tolower(c); });

    processNodes(
        "bls.get_reward_balance",
        [this, &aggSig, &signers, &signers_mutex, &lower_eth_address, &amount, &height, &signed_message, &initial_data_set](bool success, std::vector<std::string> data) {
            if (success) {
                if (data[0] == "200") {

                    // Data contains -> status, address, amount, height, bls_pubkey, signed message, signature
                    uint64_t current_amount = std::stoull(data[2]);
                    uint64_t current_height = std::stoull(data[3]);
                    if (!initial_data_set) {
                        amount = current_amount;
                        height = current_height;
                        signed_message = data[5];
                        initial_data_set = true;
                    } 
                    if (data[1] != lower_eth_address || current_amount != amount || current_height != height || data[5] != signed_message) {
                        // Log if the current data doesn't match the first set
                        oxen::log::warning(logcat, "Mismatch in data from node with bls pubkey {}. Expected address: {}, amount: {}, height: {} signed message: {}. Received address: {} amount: {}, height: {} signed_message: {}.", data[4], lower_eth_address, amount, height, signed_message, data[1], current_amount, current_height, data[5]);
                    } else {
                        bls::Signature external_signature;
                        external_signature.setStr(data[6]);
                        std::lock_guard<std::mutex> lock(signers_mutex);
                        aggSig.add(external_signature);
                        signers.push_back(data[4]);
                    
                    }
                } else {
                    oxen::log::warning(logcat, "Error message received when getting reward balance {} : {}", data[0], data[1]);
                }
            } else {
                oxen::log::warning(logcat, "OMQ not successful when getting reward balance");
            }
        },
        []{}, // No post processing for this call
        lower_eth_address
    );
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateWithdrawalResponse{lower_eth_address, amount, height, signed_message, signers, sig_str};
}
