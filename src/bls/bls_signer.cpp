#include "bls_signer.h"
#include "bls_utils.h"
#include "logging/oxen_logger.h"
#include "crypto/keccak.h"
#include <oxenc/hex.h>
#include "ethyl/utils.hpp"

static auto logcat = oxen::log::Cat("bls_signer");

const std::string proofOfPossessionTag = "BLS_SIG_TRYANDINCREMENT_POP";
const std::string rewardTag = "BLS_SIG_TRYANDINCREMENT_REWARD";
const std::string removalTag = "BLS_SIG_TRYANDINCREMENT_REMOVE";
const std::string liquidateTag = "BLS_SIG_TRYANDINCREMENT_LIQUIDATE";

std::string buildTag(const std::string& baseTag, uint32_t chainID, const std::string& contractAddress) {
    // Check if contractAddress starts with "0x" prefix
    std::string contractAddressOutput = contractAddress;
    if (contractAddressOutput.substr(0, 2) == "0x")
        contractAddressOutput = contractAddressOutput.substr(2);  // remove "0x"
    std::string concatenatedTag = "0x" + utils::toHexString(baseTag) + utils::padTo32Bytes(utils::decimalToHex(chainID), utils::PaddingDirection::LEFT) + contractAddressOutput;
    return utils::toHexString(utils::hash(concatenatedTag));
}

BLSSigner::BLSSigner() {
    initCurve();
    // This init function generates a secret key calling blsSecretKeySetByCSPRNG
    secretKey.init();
}

BLSSigner::BLSSigner(bls::SecretKey _secretKey) {
    initCurve();
    secretKey = _secretKey;
}

BLSSigner::~BLSSigner() {
}

void BLSSigner::initCurve() {
    // Initialize parameters for BN256 curve, this has a different name in our library
    bls::init(mclBn_CurveSNARK1);
    // Try and Inc method for hashing to the curve
    mclBn_setMapToMode(MCL_MAP_TO_MODE_TRY_AND_INC);
    // Our generator point was created using the old hash to curve method, redo it again using Try and Inc method
    mcl::bn::G1 gen;
    bool b;
    mcl::bn::mapToG1(&b, gen, 1);
    blsPublicKey publicKey;
    publicKey.v = *reinterpret_cast<const mclBnG1*>(&gen);

    blsSetGeneratorOfPublicKey(&publicKey);
}

bls::Signature BLSSigner::signHash(const std::array<unsigned char, 32>& hash) {
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return sig;
}

std::string BLSSigner::proofOfPossession() {
    //TODO sean put constants somewhere, source them
    const uint32_t chainID = 31337;
    const std::string contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

    std::string fullTag = buildTag(proofOfPossessionTag, chainID, contractAddress);
    std::string message = "0x" + fullTag + getPublicKeyHex();

    const std::array<unsigned char, 32> hash = BLSSigner::hash(message); // Get the hash of the publickey
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return bls_utils::SignatureToHex(sig);
}

std::string BLSSigner::getPublicKeyHex() {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return bls_utils::PublicKeyToHex(publicKey);
}

bls::PublicKey BLSSigner::getPublicKey() {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return publicKey;
}

std::array<unsigned char, 32> BLSSigner::hash(std::string in) {
    return utils::hash(in);
}

std::array<unsigned char, 32> BLSSigner::hashModulus(std::string message) {
    std::array<unsigned char, 32> hash = BLSSigner::hash(message);
    mcl::bn::Fp x;
    x.clear();
    x.setArrayMask(hash.data(), hash.size());
    std::array<unsigned char, 32> serialized_hash;
    uint8_t *hdst = serialized_hash.data();
    mclSize serializedSignatureSize = 32;
    if (x.serialize(hdst, serializedSignatureSize, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of x is zero");
    return serialized_hash;
}
