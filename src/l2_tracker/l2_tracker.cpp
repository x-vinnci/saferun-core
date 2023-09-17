#include "l2_tracker.h"
#include <thread>
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("daemon");

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

void L2Tracker::insert_in_order(const StateResponse& new_state) {
    // Check if the state with the same height already exists
    auto it = std::find_if(state_history.begin(), state_history.end(),
                           [&new_state](const StateResponse& state) {
                               return state.height == new_state.height;
                           });

    // If it doesn't exist, insert it in the appropriate location
    if (it == state_history.end()) {
        auto insert_loc = std::upper_bound(state_history.begin(), state_history.end(), new_state,
                                           [](const StateResponse& a, const StateResponse& b) {
                                               return a.height > b.height;
                                           });

        state_history.insert(insert_loc, new_state);
    }
}

void L2Tracker::update_state() {
    //TODO sean, create counter for failed state updates, if it fails too many times then throw
    try {
        // Get latest state
        StateResponse new_state = rewards_contract->State();
        insert_in_order(new_state);

        // Check for missing heights between the first and second entries
        std::vector<uint64_t> missing_heights;
        if (state_history.size() > 1) {
            uint64_t first_height = state_history[0].height;
            uint64_t second_height = state_history[1].height;

            for (uint64_t h = first_height - 1; h > second_height; --h) {
                new_state = rewards_contract->State(h);
                insert_in_order(new_state);
            }
        }
    } catch (const std::exception& e) {
        oxen::log::error(logcat, "Failed to update state: {}", e.what());
    }
}

std::pair<uint64_t, crypto::hash> L2Tracker::latest_state() {
    if(state_history.empty()) {
        throw std::runtime_error("Internal error getting latest state from l2 tracker");
    }
    crypto::hash return_hash;
    auto& latest_state = state_history.back();
    tools::hex_to_type(latest_state.state, return_hash);
    return std::make_pair(latest_state.height, return_hash);
}

bool L2Tracker::check_state_in_history(uint64_t height, const crypto::hash& state) {
    std::string state_str = tools::type_to_hex(state);
    return check_state_in_history(height, state_str);
}

bool L2Tracker::check_state_in_history(uint64_t height, const std::string& state) {
    auto it = std::find_if(state_history.begin(), state_history.end(),
        [height, &state](const StateResponse& stateResponse) {
            return stateResponse.height == height && stateResponse.state == state;
        });
    return it != state_history.end();
}


std::string L2Tracker::get_contract_address(const cryptonote::network_type nettype) {
    return std::string(get_config(nettype).ETHEREUM_REWARDS_CONTRACT);
}
