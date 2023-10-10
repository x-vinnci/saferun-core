#include "merkle_tree_creator.hpp"
#include "iostream"
#include <ethyl/utils.hpp>

extern "C" {
#include "crypto/keccak.h"
}

MerkleTreeCreator::MerkleTreeCreator() {}

void MerkleTreeCreator::addLeaf(const std::string& input) {
    tree.insert(createMerkleKeccakHash(input));
}

void MerkleTreeCreator::addLeaves(const std::map<std::string, uint64_t>& data) {
    for (const auto& [address, balance] : data) {
        std::string combined = abiEncode(address, balance);
        addLeaf(combined);
    }
}

std::string MerkleTreeCreator::abiEncode(const std::string& address, uint64_t balance) {
    
    std::string sanitized_address = address;
    // Check if input starts with "0x" prefix
    if (sanitized_address.substr(0, 2) == "0x") {
        sanitized_address = sanitized_address.substr(2);  // remove "0x" prefix for now
    }
    std::string sanitized_address_padded = utils::padTo32Bytes(sanitized_address, utils::PaddingDirection::LEFT);
    std::string balance_padded = utils::padTo32Bytes(utils::decimalToHex(balance), utils::PaddingDirection::LEFT);

    return "0x" + sanitized_address_padded + balance_padded;
}

merkle::Tree::Hash MerkleTreeCreator::createMerkleKeccakHash(const std::string& input) {
    // Compute Keccak hash using utils::hash
    std::array<unsigned char, 32> hash_result = utils::hash(input);
    
    // Convert std::array to std::vector
    std::vector<uint8_t> hash_vector(hash_result.begin(), hash_result.end());
    return merkle::Tree::Hash(hash_vector);
}

void MerkleTreeCreator::cncryptoCompressKeccak256(
    const merkle::HashT<32>& l,
    const merkle::HashT<32>& r,
    merkle::HashT<32>& out)
{
    uint8_t block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);

    // Assuming keccak function signature remains the same as in the provided utils::hash function
    keccak(block, sizeof(block), out.bytes, 32);
}

std::string MerkleTreeCreator::getRoot() {
    return tree.root().to_string();
}

size_t MerkleTreeCreator::getPathSize(size_t index) {
    return tree.path(index)->size();
}

std::string MerkleTreeCreator::getPath(size_t index) {
    return tree.path(index)->to_eth_string();
}

size_t MerkleTreeCreator::findIndex(const std::string& input) {
    return tree.find_leaf_index(createMerkleKeccakHash(input));
}

std::string MerkleTreeCreator::updateRewardsMerkleRoot() {
    //function updateRewardsMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
    std::string functionSelector = utils::getFunctionSignature("updateRewardsMerkleRoot(bytes32)");

    // Concatenate the function selector and the encoded arguments
    return functionSelector + getRoot();
}

std::string MerkleTreeCreator::validateProof(size_t index, int64_t amount) {
    //function validateProof(uint256 _quantity, bytes32[] calldata _merkleProof) external {
    std::string functionSelector = utils::getFunctionSignature("validateProof(uint256,bytes32[])");

    // Convert amount to hex string and pad it to 32 bytes
    std::string amount_padded = utils::padTo32Bytes(utils::decimalToHex(amount), utils::PaddingDirection::LEFT);
    std::string proof_location_padded = utils::padTo32Bytes(utils::decimalToHex(64), utils::PaddingDirection::LEFT);
    std::string proof_length_padded = utils::padTo32Bytes(utils::decimalToHex(getPathSize(index)), utils::PaddingDirection::LEFT);

    // Concatenate the function selector and the encoded arguments
    return functionSelector + amount_padded + proof_location_padded + proof_length_padded + getPath(index);
}
