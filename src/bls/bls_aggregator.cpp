#include "bls_aggregator.h"

#include "logging/oxen_logger.h"

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#undef MCLBN_NO_AUTOLINK
#pragma GCC diagnostic pop

static auto logcat = oxen::log::Cat("bls_aggregator");

BLSAggregator::BLSAggregator(service_nodes::service_node_list& _snl, std::shared_ptr<oxenmq::OxenMQ> _omq, std::shared_ptr<BLSSigner> _bls_signer)
    : service_node_list(_snl), omq(std::move(_omq)), bls_signer(std::move(_bls_signer)) {
}

std::vector<std::pair<std::string, std::string>> BLSAggregator::getPubkeys() {
    std::vector<std::pair<std::string, std::string>> pubkeys;
    std::mutex pubkeys_mutex;

    processNodes(
        "bls.pubkey_request",
        [this, &pubkeys, &pubkeys_mutex](bool success, const std::vector<std::string>& data) {
            if (success) {
                std::lock_guard<std::mutex> lock(pubkeys_mutex);
                pubkeys.emplace_back(data[0], data[1]);
            }
        }
    );

    return pubkeys;
}

blsRegistrationResponse BLSAggregator::registration(const std::string& senderEthAddress, const std::string& serviceNodePubkey) const {
    return blsRegistrationResponse{bls_signer->getPublicKeyHex(), bls_signer->proofOfPossession(senderEthAddress, serviceNodePubkey), senderEthAddress, serviceNodePubkey, ""};
}

void BLSAggregator::processNodes(std::string_view request_name, std::function<void(bool, const std::vector<std::string>&)> callback, const std::optional<std::string>& message) {
    std::mutex connection_mutex;
    std::condition_variable cv;
    size_t active_connections = 0;
    const size_t MAX_CONNECTIONS = 900;

    // TODO sean, change this so instead of using an iterator do a for_each_service_node_info_and proof and pass a lambda
    auto it = service_node_list.get_first_pubkey_iterator();
    auto end_it = service_node_list.get_end_pubkey_iterator();
    crypto::x25519_public_key x_pkey{0};
    uint32_t ip = 0;
    uint16_t port = 0;

    while (it != end_it) {
        service_node_list.access_proof(it->first, [&x_pkey, &ip, &port](auto& proof) {
            x_pkey = proof.pubkey_x25519;
            ip = proof.proof->public_ip;
            port = proof.proof->qnet_port;
        });
        
        //{
            //std::unique_lock<std::mutex> connection_lock(connection_mutex);
            //cv.wait(connection_lock, [&active_connections] { return active_connections < MAX_CONNECTIONS; });
        //}
        // TODO sean epee is always little, this will not work on big endian host
        boost::asio::ip::address_v4 address(oxenc::host_to_big(ip));
        oxenmq::address addr{"tcp://{}:{}"_format(address.to_string(), port), tools::view_guts(x_pkey)};

        {
            std::lock_guard<std::mutex> connection_lock(connection_mutex);
            ++active_connections;
        }
        
        auto conn = omq->connect_remote(
            addr,
            [](oxenmq::ConnectionID c) {
                // Successfully connected
            },
            [](oxenmq::ConnectionID c, std::string_view err) {
                // Failed to connect
            },
            oxenmq::AuthLevel::basic
        );

        if (message) {
            omq->request(
                conn,
                request_name,
                [this, &connection_mutex, &active_connections, &cv, &conn, callback](bool success, std::vector<std::string> data) {
                    callback(success, data);
                    std::lock_guard<std::mutex> connection_lock(connection_mutex);
                    --active_connections;
                    cv.notify_all();
                    //omq->disconnect(c);
                },
                *message
            );
        } else {
            omq->request(
                conn,
                request_name,
                [this, &connection_mutex, &active_connections, &cv, &conn, callback](bool success, std::vector<std::string> data) {
                    callback(success, data);
                    std::lock_guard<std::mutex> connection_lock(connection_mutex);
                    --active_connections;
                    cv.notify_all();
                    //omq->disconnect(c);
                }
            );
        }

        it = service_node_list.get_next_pubkey_iterator(it);
    }

    std::unique_lock<std::mutex> connection_lock(connection_mutex);
    cv.wait(connection_lock, [&active_connections] {
        return active_connections == 0;
    });
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
        [this, &aggSig, &signers, &signers_mutex, &lower_eth_address, &amount, &height, &signed_message, &initial_data_set](bool success, const std::vector<std::string>& data) {
            if (success) {
                if (data[0] == "200") {

                    // Data contains -> status, address, amount, height, bls_pubkey, signed message, signature
                    uint64_t current_amount = std::stoull(data[2]);
                    uint64_t current_height = std::stoull(data[3]);

                    signers_mutex.lock();
                    if (!initial_data_set) {
                        amount = current_amount;
                        height = current_height;
                        signed_message = data[5];
                        initial_data_set = true;
                    } 
                    signers_mutex.unlock();

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
        lower_eth_address
    );
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateWithdrawalResponse{lower_eth_address, amount, height, signed_message, signers, sig_str};
}

aggregateExitResponse BLSAggregator::aggregateExit(const std::string& bls_key) {
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    std::string signed_message = "";
    bool initial_data_set = false;

    processNodes(
        "bls.get_exit",
        [this, &aggSig, &signers, &signers_mutex, &bls_key, &signed_message, &initial_data_set](bool success, const std::vector<std::string>& data) {
            if (success) {
                if (data[0] == "200") {

                    // Data contains -> status, bls_pubkey (signer), bls_pubkey (node being removed), signed message, signature
                    signers_mutex.lock();
                    if (!initial_data_set) {
                        signed_message = data[3];
                        initial_data_set = true;
                    } 
                    signers_mutex.unlock();
                    if (data[1] != bls_key || data[3] != signed_message) {
                        // Log if the current data doesn't match the first set
                        oxen::log::warning(logcat, "Mismatch in data from node with bls pubkey {}. Expected bls_key: {}, signed message: {}. Received bls_key: {}, signed_message: {}.", data[2], bls_key, signed_message, data[1], data[3]);
                    } else {
                        bls::Signature external_signature;
                        external_signature.setStr(data[4]);
                        std::lock_guard<std::mutex> lock(signers_mutex);
                        aggSig.add(external_signature);
                        signers.push_back(data[2]);
                    
                    }
                } else {
                    oxen::log::warning(logcat, "Error message received when requesting exit {} : {}", data[0], data[1]);
                }
            } else {
                oxen::log::warning(logcat, "OMQ not successful when requesting exit");
            }
        },
        bls_key
    );
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateExitResponse{bls_key, signed_message, signers, sig_str};
}

aggregateExitResponse BLSAggregator::aggregateLiquidation(const std::string& bls_key) {
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    std::string signed_message = "";
    bool initial_data_set = false;

    processNodes(
        "bls.get_liquidation",
        [this, &aggSig, &signers, &signers_mutex, &bls_key, &signed_message, &initial_data_set](bool success, const std::vector<std::string>& data) {
            if (success) {
                if (data[0] == "200") {

                    // Data contains -> status, bls_pubkey (signer), bls_pubkey (node being removed), signed message, signature
                    signers_mutex.lock();
                    if (!initial_data_set) {
                        signed_message = data[3];
                        initial_data_set = true;
                    } 
                    signers_mutex.unlock();

                    if (data[1] != bls_key || data[3] != signed_message) {
                        // Log if the current data doesn't match the first set
                        oxen::log::warning(logcat, "Mismatch in data from node with bls pubkey {}. Expected bls_key: {}, signed message: {}. Received bls_key: {}, signed_message: {}.", data[2], bls_key, signed_message, data[1], data[3]);
                    } else {
                        bls::Signature external_signature;
                        external_signature.setStr(data[4]);
                        std::lock_guard<std::mutex> lock(signers_mutex);
                        aggSig.add(external_signature);
                        signers.push_back(data[2]);
                    
                    }
                } else {
                    oxen::log::warning(logcat, "Error message received when requesting liquidation {} : {}", data[0], data[1]);
                }
            } else {
                oxen::log::warning(logcat, "OMQ not successful when requesting liquidation");
            }
        },
        bls_key
    );
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateExitResponse{bls_key, signed_message, signers, sig_str};
}
