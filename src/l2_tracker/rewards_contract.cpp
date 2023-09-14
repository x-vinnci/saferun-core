#include "rewards_contract.h"

RewardsContract::RewardsContract(const std::string& _contractAddress, std::shared_ptr<Provider> _provider)
        : contractAddress(_contractAddress), provider(_provider) {}

StateResponse RewardsContract::State() {
    ReadCallData callData;
    callData.contractAddress = contractAddress;
    std::string functionSelector = utils::getFunctionSignature("state()");
    callData.data = functionSelector;

    std::string result = provider->callReadFunction(callData);
    std::string blockHeightHex = result.substr(2, 64); 
    std::string blockHash = result.substr(66, 64); 

    // Convert blockHeightHex to a decimal number
    uint64_t blockHeight = std::stoull(blockHeightHex, nullptr, 16);

    return StateResponse{blockHeight, blockHash};
}
