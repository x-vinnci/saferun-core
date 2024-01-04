#include "l2_tracker.h"

#include <thread>
#include <utility>

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

L2Tracker::L2Tracker() {
}

L2Tracker::L2Tracker(const cryptonote::network_type nettype, const std::shared_ptr<Provider>& _provider) 
    : rewards_contract(std::make_shared<RewardsContract>(get_contract_address(nettype), _provider)),
      stop_thread(false), review_block_height(0) {
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

void L2Tracker::insert_in_order(State&& new_state) {
    // Check if the state with the same height already exists
    auto it = std::find_if(state_history.begin(), state_history.end(),
                           [&new_state](const State& state) {
                               return state.height == new_state.height;
                           });

    // If it doesn't exist, insert it in the appropriate location
    if (it == state_history.end()) {
        auto insert_loc = std::upper_bound(state_history.begin(), state_history.end(), new_state,
                                           [](const State& a, const State& b) {
                                               return a.height > b.height;
                                           });

        state_history.insert(insert_loc, std::move(new_state)); // Use std::move here
    }
}

void L2Tracker::process_logs_for_state(State& state) {
    std::vector<RewardsLogEntry> logs = rewards_contract->Logs(state.height);
    for (const auto& log : logs) {
        auto transaction = log.getLogTransaction();
        if (transaction) {
            state.state_changes.emplace_back(*transaction);
        }
    }
}

void L2Tracker::update_state() {
    try {
        // Get latest state
        State new_state(rewards_contract->State());
        process_logs_for_state(new_state);
        insert_in_order(std::move(new_state));

        // Check for missing heights between the first and second entries
        if (state_history.size() > 1) {
            uint64_t first_height = state_history[0].height;
            uint64_t second_height = state_history[1].height;

            for (uint64_t h = first_height - 1; h > second_height; --h) {
                State missing_state(rewards_contract->State(h));
                process_logs_for_state(missing_state);
                insert_in_order(std::move(missing_state));
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

bool L2Tracker::check_state_in_history(uint64_t height, const crypto::hash& state_root) {
    std::string state_str = tools::type_to_hex(state_root);
    return check_state_in_history(height, state_str);
}

bool L2Tracker::check_state_in_history(uint64_t height, const std::string& state_root) {
    auto it = std::find_if(state_history.begin(), state_history.end(),
        [height, &state_root](const State& state) {
            return state.height == height && state.state == state_root;
        });
    return it != state_history.end();
}

void L2Tracker::initialize_transaction_review(uint64_t ethereum_height) {
    if (review_block_height != 0) {
        throw std::runtime_error(
            "Review not finalized from last block, block height currently reviewing: " 
            + std::to_string(review_block_height) 
            + " new review height: " 
            + std::to_string(ethereum_height)
        );
    }
    review_block_height = ethereum_height;
    get_review_transactions();  // Fills new_service_nodes, leave_requests, decommissions
}

bool L2Tracker::processNewServiceNodeTx(const std::string& bls_key, const std::string& eth_address, const std::string& service_node_pubkey, std::string& fail_reason) {
    if (review_block_height == 0) {
        fail_reason = "Review not initialized";
        oxen::log::error(logcat, "Failed to process new service node tx height {}", review_block_height);
        return false;
    }

    for (auto it = new_service_nodes.begin(); it != new_service_nodes.end(); ++it) {
        if (it->bls_key == bls_key && it->eth_address == eth_address && it->service_node_pubkey == service_node_pubkey) {
            new_service_nodes.erase(it);
            return true;
        }
    }

    fail_reason = "New Service Node Transaction not found bls_key: " + bls_key + " eth_address: " + eth_address + " service_node_pubkey: " + service_node_pubkey;
    return false;
}

bool L2Tracker::processServiceNodeLeaveRequestTx(const std::string& bls_key, std::string& fail_reason) {
    if (review_block_height == 0) {
        fail_reason = "Review not initialized";
        oxen::log::error(logcat, "Failed to process service node leave request tx height {}", review_block_height);
        return false;
    }

    for (auto it = leave_requests.begin(); it != leave_requests.end(); ++it) {
        if (it->bls_key == bls_key) {
            leave_requests.erase(it);
            return true;
        }
    }

    fail_reason = "Leave Request Transaction not found bls_key: " + bls_key;
    return false;
}

bool L2Tracker::processServiceNodeDecommissionTx(const std::string& bls_key, bool refund_stake, std::string& fail_reason) {
    if (review_block_height == 0) {
        fail_reason = "Review not initialized";
        oxen::log::error(logcat, "Failed to process decommission tx height {}", review_block_height);
        return false;
    }

    for (auto it = decommissions.begin(); it != decommissions.end(); ++it) {
        if (it->bls_key == bls_key && it->refund_stake == refund_stake) {
            decommissions.erase(it);
            return true;
        }
    }

    fail_reason = "Decommission Transaction not found bls_key: " + bls_key;
    return false;
}

bool L2Tracker::finalize_transaction_review() {
    if (new_service_nodes.empty() && leave_requests.empty() && decommissions.empty()) {
        review_block_height = 0;
        return true;
    }
    return false;
}


std::string L2Tracker::get_contract_address(const cryptonote::network_type nettype) {
    return std::string(get_config(nettype).ETHEREUM_REWARDS_CONTRACT);
}

void L2Tracker::get_review_transactions() {
    new_service_nodes.clear();
    leave_requests.clear();
    decommissions.clear();
    if (review_block_height == 0) {
        oxen::log::warning(logcat, "get_review_transactions called with 0 block height");
        return;
    }
    for (const auto& state : state_history) {
        if (state.height == review_block_height) {
            for (const auto& transactionVariant : state.state_changes) {
                std::visit([this](auto&& arg) {
                    using T = std::decay_t<decltype(arg)>;
                    if constexpr (std::is_same_v<T, NewServiceNodeTx>) {
                        new_service_nodes.push_back(arg);
                    } else if constexpr (std::is_same_v<T, ServiceNodeLeaveRequestTx>) {
                        leave_requests.push_back(arg);
                    } else if constexpr (std::is_same_v<T, ServiceNodeDecommissionTx>) {
                        decommissions.push_back(arg);
                    }
                }, transactionVariant);
            }
            break; // Exit the loop once the matching state is processed
        }
        if (state.height < review_block_height) {
            // State history should be ordered, if we go below our desired height then its not there so throw
            throw std::runtime_error("Did not find review height in state history");
        }
    }
}
