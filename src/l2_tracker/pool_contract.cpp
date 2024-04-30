#include "pool_contract.h"

PoolContract::PoolContract(const std::string& _contractAddress, std::shared_ptr<Provider> _provider)
        : contractAddress(_contractAddress), provider(std::move(_provider)) {}

RewardRateResponse PoolContract::RewardRate(uint64_t timestamp) {
    //uint256_t reward = provider->callContractFunction(contractAddress, "rewardRate", timestamp);
    // TODO sean get this from the contract
    // Fetch the reward rate from the smart contract
    uint64_t reward = 16500000000;
    return RewardRateResponse{timestamp, reward};
}

