#pragma once

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

#include <string>
#include <vector>

#include "cryptonote_core/service_node_list.h"
#include "bls_signer.h"
#include "bls_utils.h"
#include <oxenmq/oxenmq.h>

#include <boost/asio.hpp>
#include <oxenc/endian.h>
#include "common/string_util.h"

struct aggregateExitResponse {
    std::string bls_key;
    std::string signed_message;
    std::vector<std::string> signers_bls_pubkeys;
    std::string signature;
};

struct aggregateWithdrawalResponse {
    std::string address;
    uint64_t amount;
    uint64_t height;
    std::string signed_message;
    std::vector<std::string> signers_bls_pubkeys;
    std::string signature;
};

struct blsRegistrationResponse  {
    std::string bls_pubkey;
    std::string proof_of_possession;
    std::string address;
    std::string service_node_pubkey;
    std::string service_node_signature;
};

class BLSAggregator {
private:
    std::shared_ptr<BLSSigner> bls_signer;
    std::shared_ptr<oxenmq::OxenMQ> omq;
    service_nodes::service_node_list& service_node_list;

public:
    BLSAggregator(service_nodes::service_node_list& _snl, std::shared_ptr<oxenmq::OxenMQ> _omq, std::shared_ptr<BLSSigner> _bls_signer);

    std::vector<std::pair<std::string, std::string>> getPubkeys();
    aggregateWithdrawalResponse aggregateRewards(const std::string& address);
    aggregateExitResponse aggregateExit(const std::string& bls_key);
    aggregateExitResponse aggregateLiquidation(const std::string& bls_key);
    blsRegistrationResponse registration(const std::string& senderEthAddress, const std::string& serviceNodePubkey) const;

private:
    // Goes out to the nodes on the network and makes oxenmq requests to all of them, when getting the reply
    // `callback` will be called to process their reply and after everyone has been received it will then call
    // `postProcess`
    template <typename Callback, typename PostProcess>
    void processNodes(const std::string& request_name, Callback callback, PostProcess postProcess, const std::optional<std::string>& message = std::nullopt) {
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
        
        postProcess();
    }
// End Service Node List
};
