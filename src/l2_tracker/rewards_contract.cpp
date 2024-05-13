#include "rewards_contract.h"

#include <ethyl/utils.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

TransactionType RewardsLogEntry::getLogType() const {
    if (topics.empty()) {
        throw std::runtime_error("No topics in log entry");
    }
    // keccak256('NewServiceNode(uint64,address,(uint256,uint256),(uint256,uint256,uint256,uint16),(address,uint256)[])')
    if (topics[0] == "0xe82ed1bfc15e6602fba1a19273171c8a63c1d40b0e0117be4598167b8655498f") {
        return TransactionType::NewServiceNode;
        // keccak256('ServiceNodeRemovalRequest(uint64,address,(uint256,uint256))')
    } else if (topics[0] == "0x89477e9f4ddcb5eb9f30353ab22c31ef9a91ab33fd1ffef09aadb3458be7775d") {
        return TransactionType::ServiceNodeLeaveRequest;
        // keccak256('ServiceNodeRemoval(uint64,address,uint256,(uint256,uint256))')
    } else if (topics[0] == "0x130a7be04ef1f87b2b436f68f389bf863ee179b95399a3a8444196fab7a4e54c") {
        return TransactionType::ServiceNodeExit;
    }
    return TransactionType::Other;
}

std::optional<TransactionStateChangeVariant> RewardsLogEntry::getLogTransaction() const {
    TransactionType type = getLogType();
    switch (type) {
        case TransactionType::NewServiceNode: {
            // event NewServiceNode(uint64 indexed serviceNodeID, address recipient, BN256G1.G1Point
            // pubkey, uint256 serviceNodePubkey, uint256 serviceNodeSignature, uint16 fee,
            // Contributors[] contributors); service node id is a topic so only address, pubkeys,
            // signature, fee and contributors are in data address is 32 bytes , pubkey is 64 bytes
            // and serviceNodePubkey is 64 bytes
            //
            // The address is in 32 bytes, but actually only uses 20 bytes and the first 12 are
            // padding
            int pos = 2;  // Start after the 0x prefix
            std::string eth_address_str =
                    data.substr(pos + 24, 40);  // Skip 24 characters which are always blank
            crypto::eth_address eth_address;
            tools::hex_to_type(eth_address_str, eth_address);
            pos += 64;
            // pull 64 bytes (128 characters) for the BLS pubkey
            std::string bls_key_str = data.substr(pos, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            pos += 128;
            // pull 32 bytes (64 characters) ed pubkey
            std::string service_node_pubkey = data.substr(pos, 64);
            pos += 64;
            // pull 64 bytes (128 characters) for ed signature
            std::string signature = data.substr(pos, 128);
            pos += 128;
            // pull 32 bytes (64 characters) for fee
            std::string fee_str = data.substr(pos, 64);
            uint64_t fee = utils::fromHexStringToUint64(fee_str);
            pos += 64;
            // There are 32 bytes describing the size of contributors data here, ignore because we
            // always get the same data out of it
            pos += 64;
            // pull 32 bytes (64 characters) for the number of elements in the array
            std::vector<Contributor> contributors;
            std::string num_contributors_str = data.substr(pos, 64);

            uint64_t num_contributors = utils::fromHexStringToUint64(num_contributors_str);
            pos += 64;
            std::string contributor_address_str;
            std::string contributor_amount_str;
            for (uint64_t i = 0; i < num_contributors; ++i) {
                // Each loop iteration processes one contributor
                contributor_address_str = data.substr(pos + 24, 40);
                crypto::eth_address contributor_address;
                tools::hex_to_type(contributor_address_str, contributor_address);
                pos += 64;
                contributor_amount_str = data.substr(pos, 64);
                uint64_t contributor_amount = utils::fromHexStringToUint64(contributor_amount_str);
                pos += 64;
                contributors.emplace_back(contributor_address, contributor_amount);
            }

            return NewServiceNodeTx(
                    bls_key, eth_address, service_node_pubkey, signature, fee, contributors);
        }
        case TransactionType::ServiceNodeLeaveRequest: {
            // event ServiceNodeRemovalRequest(uint64 indexed serviceNodeID, address recipient,
            // BN256G1.G1Point pubkey); service node id is a topic so only address and pubkey are in
            // data address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128
            // characters)
            std::string bls_key_str = data.substr(64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeLeaveRequestTx(bls_key);
        }
        case TransactionType::ServiceNodeDeregister: {
            // event ServiceNodeLiquidated(uint64 indexed serviceNodeID, address recipient,
            // BN256G1.G1Point pubkey); service node id is a topic so only address and pubkey are in
            // data address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128
            // characters)
            std::string bls_key_str = data.substr(64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeDeregisterTx(bls_key);
        }
        case TransactionType::ServiceNodeExit: {
            // event ServiceNodeRemoval(uint64 indexed serviceNodeID, address recipient, uint256
            // returnedAmount, BN256G1.G1Point pubkey); address is 32 bytes, amount is 32 bytes and
            // pubkey is 64 bytes
            //
            // The address is in 32 bytes, but actually only uses 20 bytes and the first 12 are
            // padding
            std::string eth_address_str = data.substr(2 + 24, 40);
            crypto::eth_address eth_address;
            tools::hex_to_type(eth_address_str, eth_address);
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 32 bytes (64
            // characters)
            std::string amount_str = data.substr(64 + 2, 64);
            uint64_t amount = utils::fromHexStringToUint64(amount_str);
            // pull 64 bytes (128 characters)
            std::string bls_key_str = data.substr(64 + 64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeExitTx(eth_address, amount, bls_key);
        }
        default: return std::nullopt;
    }
}

RewardsContract::RewardsContract(
        const std::string& _contractAddress, std::shared_ptr<Provider> _provider) :
        contractAddress(_contractAddress), provider(std::move(_provider)) {}

StateResponse RewardsContract::State() {
    return State(provider->getLatestHeight());
}

StateResponse RewardsContract::State(uint64_t height) {
    std::string blockHash = provider->getContractStorageRoot(contractAddress, height);
    // Check if blockHash starts with "0x" and remove it
    if (blockHash.size() >= 2 && blockHash[0] == '0' && blockHash[1] == 'x') {
        blockHash = blockHash.substr(2);  // Skip the first two characters
    }
    return StateResponse{height, blockHash};
}

std::vector<RewardsLogEntry> RewardsContract::Logs(uint64_t height) {
    std::vector<RewardsLogEntry> logEntries;
    // Make the RPC call
    const auto logs = provider->getLogs(height, contractAddress);

    for (const auto& log : logs) {
        logEntries.emplace_back(RewardsLogEntry(log));
    }

    return logEntries;
}
