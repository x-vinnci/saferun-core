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

#include <memory>
#include <oxenmq/oxenmq.h>
#include "cryptonote_config.h"

class BLSSigner {
private:
    bls::SecretKey secretKey;

    uint32_t chainID;
    std::string contractAddress;

    void initCurve();

public:
    BLSSigner(const cryptonote::network_type nettype);
    BLSSigner(const cryptonote::network_type nettype, bls::SecretKey _secretKey);
    ~BLSSigner();

    bls::Signature signHash(const std::array<unsigned char, 32>& hash);
    std::string proofOfPossession();
    std::string getPublicKeyHex();
    bls::PublicKey getPublicKey();

    static std::array<unsigned char, 32> hash(std::string in);
    static std::array<unsigned char, 32> hashModulus(std::string message);


private:

// END
};
