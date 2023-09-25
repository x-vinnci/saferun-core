#include "bls_aggregator.h"
#include "bls_signer.h"
#include "bls_utils.h"

#include "common/string_util.h"
#include "logging/oxen_logger.h"
#include <boost/asio.hpp>
#include <oxenc/endian.h>

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

aggregateResponse BLSAggregator::aggregateSignatures(const std::string& message) {
    const std::array<unsigned char, 32> hash = BLSSigner::hash(message);
    std::mutex signers_mutex, connection_mutex;
    std::condition_variable cv;
    size_t active_connections = 0;
    const size_t MAX_CONNECTIONS = 900;
    bls::Signature aggSig;
    aggSig.clear();

    std::vector<int64_t> signers;

    auto it = service_node_list.get_first_pubkey_iterator();
    auto end_it = service_node_list.get_end_pubkey_iterator();
    crypto::x25519_public_key x_pkey{0};
    uint32_t ip;
    uint16_t port;
    int64_t signers_index = 0;
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
        boost::asio::ip::address_v4 address(oxenc::host_to_big(ip));
        oxenmq::address addr{"tcp://{}:{}"_format(address.to_string(), port), tools::view_guts(x_pkey)};

        {
            std::lock_guard<std::mutex> connection_lock(connection_mutex);
            ++active_connections;
        }
        auto conn = omq->connect_remote(
            addr,
            [this, &aggSig, &signers, &signers_mutex, &connection_mutex, signers_index, &active_connections, &cv, &message](oxenmq::ConnectionID c) {
                // Successfully connected
                oxen::log::info(logcat, "TODO sean remove this: successuflly connected");
                omq->request(
                        c,
                        "bls.signature_request",
                        [this, &aggSig, &signers, &signers_mutex, &connection_mutex, signers_index, &active_connections, &cv, &c](bool success, std::vector<std::string> data) {
                            oxen::log::info(logcat, "TODO sean remove this: successuflly response {}", signers_index);
                            oxen::log::debug( logcat, "bls signature response received");
                            if (success) {
                                bls::Signature external_signature;
                                external_signature.setStr(data[0]);
                                std::lock_guard<std::mutex> lock(signers_mutex);
                                aggSig.add(external_signature);
                                signers.push_back(signers_index);
                            }
                            std::lock_guard<std::mutex> connection_lock(connection_mutex);
                            oxen::log::info(logcat, "TODO sean remove this: decrementing active connections");
                            --active_connections;
                            cv.notify_all();
                            //omq->disconnect(c);
                        },
                        message
                        );
            },
            [&active_connections, &cv, &connection_mutex](oxenmq::ConnectionID c, std::string_view err) {
                // Failed to connect
                oxen::log::debug(logcat, "Failed to connect {}", err);
                std::lock_guard<std::mutex> connection_lock(connection_mutex);
                --active_connections;
                cv.notify_all();
            },
            oxenmq::AuthLevel::basic);
        it = service_node_list.get_next_pubkey_iterator(it);
        signers_index++;
    }
    std::unique_lock<std::mutex> connection_lock(connection_mutex);
    cv.wait(connection_lock, [&active_connections] {
        oxen::log::info(logcat, "TODO sean remove this: {}", active_connections);
        return active_connections == 0;
    });
    const auto non_signers = findNonSigners(signers);
    const auto my_signature = bls_signer->signHash(hash);
    aggSig.add(my_signature);
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateResponse{non_signers, sig_str};
};

std::vector<int64_t> BLSAggregator::findNonSigners(const std::vector<int64_t>& indices) {
    std::vector<int64_t> nonSignerIndices = {};
    for (int64_t i = 0; i < static_cast<int64_t>(service_node_list.get_service_node_count()); ++i) {
        if (std::find(indices.begin(), indices.end(), i) == indices.end()) {
            nonSignerIndices.push_back(i);
        }
    }
    return nonSignerIndices;
}
