#include "bls_utils.h"
#include <oxenc/hex.h>

std::string bls_utils::SignatureToHex(bls::Signature sig) {
    mclSize serializedSignatureSize = 32;
    std::vector<unsigned char> serialized_signature(serializedSignatureSize*4);
    uint8_t *dst = serialized_signature.data();
    const blsSignature* blssig = sig.getPtr();  
    const mcl::bn::G2* g2Point = reinterpret_cast<const mcl::bn::G2*>(&blssig->v);
    mcl::bn::G2 g2Point2 = *g2Point;
    g2Point2.normalize();
    if (g2Point2.x.a.serialize(dst, serializedSignatureSize, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of x.a is zero");
    if (g2Point2.x.b.serialize(dst + serializedSignatureSize, serializedSignatureSize, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of x.b is zero");
    if (g2Point2.y.a.serialize(dst + serializedSignatureSize * 2, serializedSignatureSize, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of y.a is zero");
    if (g2Point2.y.b.serialize(dst + serializedSignatureSize * 3, serializedSignatureSize, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of y.b is zero");
    return oxenc::to_hex(serialized_signature.begin(), serialized_signature.end());
}

std::string bls_utils::PublicKeyToHex(bls::PublicKey publicKey) {
    mclSize serializedPublicKeySize = 32;
    std::vector<unsigned char> serialized_pubkey(serializedPublicKeySize*2);
    uint8_t *dst = serialized_pubkey.data();
    const blsPublicKey* pub = publicKey.getPtr();  
    const mcl::bn::G1* g1Point = reinterpret_cast<const mcl::bn::G1*>(&pub->v);
    mcl::bn::G1 g1Point2 = *g1Point;
    g1Point2.normalize();
    if (g1Point2.x.serialize(dst, serializedPublicKeySize, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of x is zero");
    if (g1Point2.y.serialize(dst + serializedPublicKeySize, serializedPublicKeySize, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of y is zero");

    return oxenc::to_hex(serialized_pubkey.begin(), serialized_pubkey.end());
}

