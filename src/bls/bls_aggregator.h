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

class BLSAggregator {
private:
    std::shared_ptr<BLSSigner> bls_signer;
    std::shared_ptr<oxenmq::OxenMQ> omq;
    service_nodes::service_node_list& service_node_list;
public:
    BLSAggregator(service_nodes::service_node_list& snl, std::shared_ptr<oxenmq::OxenMQ> omq_ptr);
    ~BLSAggregator();

    std::string aggregatePubkeyHex();
    std::string aggregateSignatures(const std::string& message);

    std::vector<int64_t> findNonSigners(const std::vector<int64_t>& indices);

// End Service Node List
};
