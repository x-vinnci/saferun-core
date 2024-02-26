#pragma once
#include <string>
#include <memory>
#include <variant>

#include <crypto/crypto.h>

#include <ethyl/provider.hpp>
#include <ethyl/logs.hpp>

enum class TransactionType {
    NewServiceNode,
    ServiceNodeLeaveRequest,
    ServiceNodeDeregister,
    Other
};

class NewServiceNodeTx {
public:
    std::string bls_key;
    crypto::eth_address eth_address;
    std::string service_node_pubkey;
    std::string signature;

    NewServiceNodeTx(const std::string& _bls_key, const crypto::eth_address& _eth_address, const std::string& _service_node_pubkey, const std::string& _signature)
        : bls_key(_bls_key), eth_address(_eth_address), service_node_pubkey(_service_node_pubkey), signature(_signature) {}
};

class ServiceNodeLeaveRequestTx {
public:
    std::string bls_key;

    ServiceNodeLeaveRequestTx(const std::string& _bls_key)
        : bls_key(_bls_key) {}
};

class ServiceNodeDeregisterTx {
public:
    std::string bls_key;

    ServiceNodeDeregisterTx(const std::string& _bls_key)
        : bls_key(_bls_key) {}
};

using TransactionStateChangeVariant = std::variant<NewServiceNodeTx, ServiceNodeLeaveRequestTx, ServiceNodeDeregisterTx>;


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
    StateResponse State(uint64_t height);

    std::vector<RewardsLogEntry> Logs(uint64_t height);

private:
    std::string contractAddress;
    std::shared_ptr<Provider> provider;
};
