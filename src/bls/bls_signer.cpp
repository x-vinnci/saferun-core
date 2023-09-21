#include "bls_signer.h"
#include "bls_utils.h"
#include "logging/oxen_logger.h"
#include "crypto/keccak.h"
#include <oxenc/hex.h>

static auto logcat = oxen::log::Cat("bls_signer");

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

void BLSSigner::initOMQ(std::shared_ptr<oxenmq::OxenMQ> omq) {
    omq->add_category("bls", oxenmq::Access{oxenmq::AuthLevel::none})
        .add_request_command("signature_request", [&](oxenmq::Message& m) {
            oxen::log::debug(logcat, "Received omq signature request");
            if (m.data.size() != 1)
                m.send_reply(
                    "400",
                    "Bad request: BLS commands must have only one data part "
                    "(received " +
                    std::to_string(m.data.size()) + ")");
            const auto h = hash(std::string(m.data[0]));
            m.send_reply(signHash(h).getStr());
        });
}

bls::Signature BLSSigner::signHash(const std::array<unsigned char, 32>& hash) {
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return sig;
}

std::string BLSSigner::proofOfPossession() {
    const std::array<unsigned char, 32> hash = BLSSigner::hash("0x" + getPublicKeyHex()); // Get the hash of the publickey
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
    std::vector<unsigned char> bytes;

    // Check for "0x" prefix and if exists, convert the hex to bytes
    // TODO sean from_hex wont work with 0x prefix
    if(in.size() >= 2 && in[0] == '0' && in[1] == 'x') {
        std::string bytes = oxenc::from_hex(in);
        in = bytes;
    }

    std::array<unsigned char, 32> hash;
    keccak(reinterpret_cast<const uint8_t*>(in.c_str()), in.size(), hash.data(), 32);
    return hash;
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
