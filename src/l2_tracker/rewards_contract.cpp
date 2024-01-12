#include "rewards_contract.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

TransactionType RewardsLogEntry::getLogType() const {
    if (topics.empty()) {
        throw std::runtime_error("No topics in log entry");
    }
    // keccak256('NewServiceNode(uint64,address,BN256G1.G1Point,uint256,uint256)')
    if (topics[0] == "da543ad9a040217dd88f378dc7fb7759316d2cf046a7eb1106294e6a30761458") {
        return TransactionType::NewServiceNode;
    // keccak256('ServiceNodeRemovalRequest(uint64,address,BN256G1.G1Point)')
    } else if (topics[0] == "cea31df077839a5b6d4f079cb9d9e37a75fd2e0494232d8b3b90c3b77eb2f08d") {
        return TransactionType::ServiceNodeLeaveRequest;
    // keccak256('ServiceNodeLiquidated(uint64,address,BN256G1.G1Point)')
    } else if (topics[0] == "5d7e17cd2edcc6334f540934c0f7150c32f6655120e51ab941b585014b28679a") {
        return TransactionType::ServiceNodeDeregister;
    }
    return TransactionType::Other;
}

std::optional<TransactionStateChangeVariant> RewardsLogEntry::getLogTransaction() const {
    TransactionType type = getLogType();
    switch (type) {
        case TransactionType::NewServiceNode: {
            // event NewServiceNode(uint64 indexed serviceNodeID, address recipient, BN256G1.G1Point pubkey, uint256 serviceNodePubkey, uint256 serviceNodeSignature);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes , pubkey is 64 bytes and serviceNodePubkey is 32 bytes
            //
            // pull 32 bytes from start
            std::string eth_address = data.substr(2, 64);
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128 characters)
            std::string bls_key = data.substr(64 + 2, 128);
            // pull 32 bytes (64 characters)
            std::string service_node_pubkey = data.substr(128 + 64 + 2, 64);
            // pull 32 bytes (64 characters)
            std::string signature = data.substr(128 + 64 + 64 + 2, 64);
            return NewServiceNodeTx(bls_key, eth_address, service_node_pubkey, signature);
        }
        case TransactionType::ServiceNodeLeaveRequest: {
            // event ServiceNodeRemovalRequest(uint64 indexed serviceNodeID, address recipient, BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128 characters)
            std::string bls_key = data.substr(64 + 2, 128);
            return ServiceNodeLeaveRequestTx(bls_key);
        }
        case TransactionType::ServiceNodeDeregister: {
            // event ServiceNodeLiquidated(uint64 indexed serviceNodeID, address recipient, BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128 characters)
            std::string bls_key = data.substr(64 + 2, 128);
            return ServiceNodeDeregisterTx(bls_key);
        }
        default:
            return std::nullopt;
    }
}

RewardsContract::RewardsContract(const std::string& _contractAddress, std::shared_ptr<Provider> _provider)
        : contractAddress(_contractAddress), provider(std::move(_provider)) {}

StateResponse RewardsContract::State() {
    return State(std::nullopt);
}

StateResponse RewardsContract::State(std::optional<uint64_t> height) {
    ReadCallData callData;
    callData.contractAddress = contractAddress;
    std::string functionSelector = utils::getFunctionSignature("state()");
    callData.data = functionSelector;

    std::string result;
    if (height) {
        result = provider->callReadFunction(callData, *height); 
    } else {
        result = provider->callReadFunction(callData); 
    }

    if (result.size() != 130) {
        throw std::runtime_error("L2 State returned invalid data");
    }

    std::string blockHeightHex = result.substr(2, 64); 
    std::string blockHash = result.substr(66, 64); 

    // Convert blockHeightHex to a decimal number
    uint64_t blockHeight = std::stoull(blockHeightHex, nullptr, 16);
    
    return StateResponse{blockHeight, blockHash};
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

