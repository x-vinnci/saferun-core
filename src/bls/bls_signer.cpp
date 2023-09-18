#include "bls_signer.h"
#include "logging/oxen_logger.h"

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
    bls::init(mclBn_CurveSNARK1);
    mclBn_setMapToMode(MCL_MAP_TO_MODE_TRY_AND_INC);
    mcl::bn::G1 gen;
    bool b;
    mcl::bn::mapToG1(&b, gen, 1);
    blsPublicKey publicKey;
    publicKey.v = *reinterpret_cast<const mclBnG1*>(&gen); // Cast gen to mclBnG1 and assign it to publicKey.v

    blsSetGeneratorOfPublicKey(&publicKey);
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
    if(in.size() >= 2 && in[0] == '0' && in[1] == 'x') {
        bytes = oxenc::from_hex(in);
        in = std::string(bytes.begin(), bytes.end());
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
