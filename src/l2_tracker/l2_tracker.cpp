#include "l2_tracker.h"
#include <thread>

L2Tracker::L2Tracker() {
}

L2Tracker::L2Tracker(const cryptonote::network_type nettype, const std::shared_ptr<Provider>& _provider) 
    : rewards_contract(std::make_shared<RewardsContract>(get_contract_address(nettype), _provider)),
      stop_thread(false) {
    update_thread = std::thread(&L2Tracker::update_state_thread, this);
}
        
L2Tracker::~L2Tracker() {
    stop_thread.store(true);
    if (update_thread.joinable()) {
        update_thread.join();
    }
}

void L2Tracker::update_state_thread() {
    while (!stop_thread.load()) {
        update_state();
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void L2Tracker::update_state() {
    state_history.emplace_back(rewards_contract->State());
    StateResponse new_state = rewards_contract->State();
    // Check if the state with the same height already exists
    auto it = std::find_if(state_history.begin(), state_history.end(),
                           [&new_state](const StateResponse& state) {
                               return state.height == new_state.height;
                           });

    // If it doesn't exist, emplace it back
    if (it == state_history.end()) {
        state_history.emplace_back(new_state);
    }
}

std::pair<uint64_t, crypto::hash> L2Tracker::latest_state() {
    if(state_history.empty()) {
        throw std::runtime_error("Internal error getting latest state from l2 tracker");
    }
    crypto::hash return_hash;
    tools::hex_to_type(state_history.back().state, return_hash);
    return std::make_pair(6969, return_hash);
}


std::string L2Tracker::get_contract_address(const cryptonote::network_type nettype) {
    return std::string(get_config(nettype).ETHEREUM_REWARDS_CONTRACT);
}
