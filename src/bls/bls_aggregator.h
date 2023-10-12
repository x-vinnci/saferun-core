#pragma once

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#undef MCLBN_NO_AUTOLINK
#pragma GCC diagnostic pop

#include <string>
#include <vector>

#include "cryptonote_core/service_node_list.h"
#include "bls_signer.h"
#include <oxenmq/oxenmq.h>

struct aggregateResponse {
    std::vector<int64_t> non_signers;
    std::string signature;
};

struct aggregateMerkleResponse {
    std::string merkle_root;
    std::vector<int64_t> non_signers;
    std::string signature;
};

class BLSAggregator {
private:
    std::shared_ptr<BLSSigner> bls_signer;
    std::shared_ptr<oxenmq::OxenMQ> omq;
    service_nodes::service_node_list& service_node_list;
public:
    BLSAggregator(service_nodes::service_node_list& _snl, std::shared_ptr<oxenmq::OxenMQ> _omq, std::shared_ptr<BLSSigner> _bls_signer);
    ~BLSAggregator();

    std::string aggregatePubkeyHex();
    aggregateResponse aggregateSignatures(const std::string& message);
    aggregateMerkleResponse aggregateMerkleRewards(const std::string& our_merkle_root);

    std::vector<int64_t> findNonSigners(const std::vector<int64_t>& indices);

// End Service Node List
};
