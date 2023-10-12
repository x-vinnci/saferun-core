#pragma once

#include <array>
#include <vector>
#include <string>
#include <map>
#include "merklecpp.h"

class MerkleTreeCreator {
public:
    MerkleTreeCreator();

    void addLeaf(const std::string& input);
    void addRewardsLeaf(const std::string& address, const uint64_t balance);
    void addLeaves(const std::map<std::string, uint64_t>& data);

    merkle::Tree::Hash createMerkleKeccakHash(const std::string& input);

    std::string getRoot();
    std::string getPath(size_t index);
    size_t getPathSize(size_t index);
    size_t findIndex(const std::string& input);

    // For interacting with smart contract
    std::string updateRewardsMerkleRoot();
    std::string validateProof(size_t index, int64_t amount);

    std::string abiEncode(const std::string& address, uint64_t balance);

    static inline void cncryptoCompressKeccak256(
        const merkle::HashT<32>& l,
        const merkle::HashT<32>& r,
        merkle::HashT<32>& out
    );

    merkle::TreeT<32, cncryptoCompressKeccak256> tree;
};

