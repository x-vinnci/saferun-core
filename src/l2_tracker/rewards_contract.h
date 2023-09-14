#pragma once
#include <string>
#include <memory>

//#include "transaction.hpp"
#include <ethyl/provider.hpp>

struct StateResponse {
    uint64_t height;
    std::string state;
};

class RewardsContract {
public:
    // Constructor
    RewardsContract(const std::string& _contractAddress, std::shared_ptr<Provider> _provider);

    StateResponse State();
    StateResponse State(std::optional<uint64_t> height);

private:
    std::string contractAddress;
    std::shared_ptr<Provider> provider;
};
