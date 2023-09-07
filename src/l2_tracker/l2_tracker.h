#pragma once

#include "rewards_contract.h"
#include "l2_tracker.h"

#include "cryptonote_config.h"

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

    void L2Tracker::update_state_thread();
    void update_state();

private:
    static std::string get_contract_address(const cryptonote::network_type nettype);

// END
};
