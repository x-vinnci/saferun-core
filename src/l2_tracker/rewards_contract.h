#pragma once
#include <string>
#include <memory>
#include <variant>

#include <ethyl/provider.hpp>
#include <ethyl/logs.hpp>

enum class TransactionType {
    NewServiceNode,
    ServiceNodeLeaveRequest,
    ServiceNodeDecommission,
    Other
};

class NewServiceNodeTx {
public:
    std::string bls_key;
    std::string eth_address;
    std::string service_node_pubkey;

    NewServiceNodeTx(const std::string& _bls_key, const std::string& _eth_address, const std::string& _service_node_pubkey)
        : bls_key(_bls_key), eth_address(_eth_address), service_node_pubkey(_service_node_pubkey) {}
};

class ServiceNodeLeaveRequestTx {
public:
    std::string bls_key;

    ServiceNodeLeaveRequestTx(const std::string& _bls_key)
        : bls_key(_bls_key) {}
};

class ServiceNodeDecommissionTx {
public:
    std::string bls_key;
    bool refund_stake;

    ServiceNodeDecommissionTx(const std::string& _bls_key, bool _refund_stake)
        : bls_key(_bls_key), refund_stake(_refund_stake) {}
};

using TransactionStateChangeVariant = std::variant<NewServiceNodeTx, ServiceNodeLeaveRequestTx, ServiceNodeDecommissionTx>;


class RewardsLogEntry : public LogEntry {
public:
    RewardsLogEntry(const LogEntry& log) : LogEntry(log) {}
    TransactionType getLogType() const;
    std::optional<TransactionStateChangeVariant> getLogTransaction() const;
};

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

    std::vector<RewardsLogEntry> Logs(uint64_t height);

private:
    std::string contractAddress;
    std::shared_ptr<Provider> provider;
};
