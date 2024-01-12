#pragma once

#include "rewards_contract.h"
#include "l2_tracker.h"
#include "crypto/hash.h"

#include "cryptonote_config.h"


struct State {
    uint64_t height;
    std::string state;
    std::vector<TransactionStateChangeVariant> state_changes; // List of transactions that changed the state this block

    State(uint64_t _height, const std::string& _state, const std::vector<TransactionStateChangeVariant >& _state_changes)
        : height(_height), state(_state), state_changes(_state_changes) {}
    State(const StateResponse& _state_response)
        : height(_state_response.height), state(_state_response.state) {}
};


class L2Tracker {
private:
    std::shared_ptr<RewardsContract> rewards_contract;
    std::vector<State> state_history;
    std::atomic<bool> stop_thread;
    std::thread update_thread;

    uint64_t review_block_height;
    std::vector<NewServiceNodeTx> new_service_nodes;
    std::vector<ServiceNodeLeaveRequestTx> leave_requests;
    std::vector<ServiceNodeDeregisterTx> deregs;

public:
    L2Tracker();
    L2Tracker(const cryptonote::network_type nettype, const std::shared_ptr<Provider>& client);
    ~L2Tracker();

    void update_state_thread();
    void update_state();
    void insert_in_order(State&& new_state);

    void process_logs_for_state(State& state);

    bool check_state_in_history(uint64_t height, const crypto::hash& state_root);
    bool check_state_in_history(uint64_t height, const std::string& state_root);

    // These functions check whether transactions on the oxen chain should be there.
    // Call initialize before we loop, then for each transaction call processTransactionType
    // and the tracker will make sure that it should actually be on the oxen blockchain
    // at that height. When done looping call the finalize function which will 
    // then check that all transactions have been accounted for.
    void initialize_transaction_review(uint64_t ethereum_height);
    bool processNewServiceNodeTx(const std::string& bls_key, const std::string& eth_address, const std::string& service_node_pubkey, std::string& fail_reason);
    bool processServiceNodeLeaveRequestTx(const std::string& bls_key, std::string& fail_reason);
    bool processServiceNodeDeregisterTx(const std::string& bls_key, bool refund_stake, std::string& fail_reason);

    bool finalize_transaction_review();

    std::pair<uint64_t, crypto::hash> latest_state();
    std::vector<TransactionStateChangeVariant> get_block_transactions(uint64_t begin_height, uint64_t end_height);

private:
    static std::string get_contract_address(const cryptonote::network_type nettype);
    void get_review_transactions();
// END
};
