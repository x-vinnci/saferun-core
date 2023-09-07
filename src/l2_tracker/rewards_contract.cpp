#include "rewards_contract.h"



RewardsContract::RewardsContract(const std::string& _contractAddress, std::shared_ptr<Provider> _provider)
        : contractAddress(_contractAddress), provider(_provider) {}

StateResponse RewardsContract::State() {
    ReadCallData callData;
    callData.contractAddress = contractAddress;
    std::string functionSelector = utils::getFunctionSignature("state()");
    callData.data = functionSelector;
    return StateResponse{0, provider->callReadFunction(callData)};
}
