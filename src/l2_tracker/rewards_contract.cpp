#include "rewards_contract.h"

RewardsContract::RewardsContract(const std::string& _contractAddress, std::shared_ptr<Provider> _provider)
        : contractAddress(_contractAddress), provider(_provider) {}

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

