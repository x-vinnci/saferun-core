#pragma once

#include "rewards_contract.h"
#include "l2_tracker.h"
#include "crypto/hash.h"

#include "cryptonote_config.h"

class NewServiceNodeTx {
public:
    std::string bls_key;
    std::string eth_address;
    std::string service_node_pubkey;

    NewServiceNodeTx(const std::string& bls_key, const std::string& eth_address, const std::string& service_node_pubkey)
        : bls_key(bls_key), eth_address(eth_address), service_node_pubkey(service_node_pubkey) {}
};

class ServiceNodeLeaveRequestTx {
public:
    uint8_t version;
    std::string bls_key;

    ServiceNodeLeaveRequestTx(uint8_t version, const std::string& bls_key)
        : version(version), bls_key(bls_key) {}
};

class ServiceNodeDecommissionTx {
public:
    uint8_t version;
    std::string bls_key;
    bool refund_stake;

    ServiceNodeDecommissionTx(uint8_t version, const std::string& bls_key, bool refund_stake)
        : version(version), bls_key(bls_key), refund_stake(refund_stake) {}
};


class L2Tracker {
private:
    std::shared_ptr<RewardsContract> rewards_contract;
    std::vector<StateResponse> state_history;
    std::atomic<bool> stop_thread;
    std::thread update_thread;

public:
    L2Tracker();
    L2Tracker(const cryptonote::network_type nettype, const std::shared_ptr<Provider>& client);
    ~L2Tracker();

    void update_state_thread();
    void update_state();
    void insert_in_order(const StateResponse& new_state);

    bool check_state_in_history(uint64_t height, const crypto::hash& state);
    bool check_state_in_history(uint64_t height, const std::string& state);

    // These functions check whether transactions on the oxen chain should be there.
    // Call initialize before we loop, then for each transaction call processTransactionType
    // and the tracker will make sure that it should actually be on the oxen blockchain
    // at that height. When done looping call the finalize function which will 
    // then check that all transactions have been accounted for.
    void initialize_transaction_review(uint64_t ethereum_height);
    bool processNewServiceNodeTx(const std::string& bls_key, const std::string& eth_address, const std::string& service_node_pubkey, std::string& fail_reason);
    bool processServiceNodeLeaveRequestTx(const std::string& bls_key, std::string& fail_reason);
    bool processServiceNodeDecommissionTx(const std::string& bls_key, bool refund_stake, std::string& fail_reason);

    bool finalize_transaction_review();

    std::pair<uint64_t, crypto::hash> latest_state();

private:
    static std::string get_contract_address(const cryptonote::network_type nettype);
    void get_review_transactions();

    uint64_t review_block_height;
    std::vector<NewServiceNodeTx> new_service_nodes;
    std::vector<ServiceNodeLeaveRequestTx> leave_requests;
    std::vector<ServiceNodeDecommissionTx> decommissions;

// END
};
