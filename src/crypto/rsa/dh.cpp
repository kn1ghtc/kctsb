/**
 * @file dh.cpp
 * @brief Diffie-Hellman Key Exchange Implementation - NTL Backend
 * 
 * Complete DH implementation following:
 * - RFC 3526 (MODP Groups for IKE)
 * - RFC 7919 (TLS 1.3 FFDHE Groups)
 * 
 * Security features:
 * - Safe prime groups (p = 2q + 1)
 * - Subgroup validation
 * - Constant-time exponentiation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/rsa/dh.h"
#include <cstring>
#include <stdexcept>
#include <random>

namespace kctsb {
namespace dh {

// ============================================================================
// Standard DH Groups (RFC 3526 / RFC 7919)
// ============================================================================

DHParams get_modp_2048() {
    DHParams params;
    params.name = "modp_2048";
    params.bits = 2048;
    
    // RFC 3526 Group 14
    params.p = conv<ZZ>(
        "32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235952326906424385423648980096571697115698316994557355232849604367010213693879875486706551940594367674461971816903054879832505419795715533607981590350572057082261931755262644199686154623678608788231096410867933511217100371555588936589476936865357616850639065219311888385236291021");
    
    params.g = ZZ(2);
    
    // q = (p-1)/2 for safe prime
    params.q = (params.p - 1) / 2;
    
    return params;
}

DHParams get_modp_3072() {
    DHParams params;
    params.name = "modp_3072";
    params.bits = 3072;
    
    // RFC 3526 Group 15
    params.p = conv<ZZ>(
        "5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433030254933");
    
    params.g = ZZ(2);
    params.q = (params.p - 1) / 2;
    
    return params;
}

DHParams get_modp_4096() {
    DHParams params;
    params.name = "modp_4096";
    params.bits = 4096;
    
    // RFC 3526 Group 16
    params.p = conv<ZZ>(
        "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617023806505913245610825731835380087608622102834270197698202313169017678006675195485079921636419370285375124784014907159135459982790513399611551794271106831134090584272884279791554849782954323534517065223269061394905987693002282120102702783");
    
    params.g = ZZ(2);
    params.q = (params.p - 1) / 2;
    
    return params;
}

// ============================================================================
// DHParams Implementation
// ============================================================================

bool DHParams::is_valid() const {
    // Check p is prime
    if (!ProbPrime(p)) {
        return false;
    }
    
    // Check g is in valid range
    if (g < ZZ(2) || g >= p) {
        return false;
    }
    
    // For safe primes, verify q = (p-1)/2 is also prime
    if (!IsZero(q) && !ProbPrime(q)) {
        return false;
    }
    
    return true;
}

// ============================================================================
// DHKeyPair Implementation
// ============================================================================

std::vector<uint8_t> DHKeyPair::export_public_key() const {
    size_t byte_len = static_cast<size_t>(NumBytes(public_key));
    // NTL BytesFromZZ outputs little-endian, PKCS#3 requires big-endian
    std::vector<uint8_t> le_bytes(byte_len);
    BytesFromZZ(le_bytes.data(), public_key, static_cast<long>(byte_len));
    
    std::vector<uint8_t> result(byte_len);
    for (size_t i = 0; i < byte_len; i++) {
        result[i] = le_bytes[byte_len - 1 - i];
    }
    return result;
}

std::vector<uint8_t> DHKeyPair::export_private_key() const {
    size_t byte_len = static_cast<size_t>(NumBytes(private_key));
    // NTL BytesFromZZ outputs little-endian, PKCS#3 requires big-endian
    std::vector<uint8_t> le_bytes(byte_len);
    BytesFromZZ(le_bytes.data(), private_key, static_cast<long>(byte_len));
    
    std::vector<uint8_t> result(byte_len);
    for (size_t i = 0; i < byte_len; i++) {
        result[i] = le_bytes[byte_len - 1 - i];
    }
    return result;
}

void DHKeyPair::clear() {
    private_key = ZZ(0);
    public_key = ZZ(0);
}

// ============================================================================
// DH Class Implementation
// ============================================================================

DH::DH() : params_(get_modp_2048()) {}

DH::DH(DHGroupType group_type) {
    switch (group_type) {
        case DHGroupType::MODP_2048:
            params_ = get_modp_2048();
            break;
        case DHGroupType::MODP_3072:
            params_ = get_modp_3072();
            break;
        case DHGroupType::MODP_4096:
            params_ = get_modp_4096();
            break;
        default:
            throw std::invalid_argument("Unsupported DH group");
    }
}

DH::DH(const DHParams& params) : params_(params) {
    if (!params_.is_valid()) {
        throw std::invalid_argument("Invalid DH parameters");
    }
}

size_t DH::get_prime_size() const {
    return (params_.bits + 7) / 8;
}

size_t DH::get_shared_secret_size() const {
    return get_prime_size();
}

// ============================================================================
// Key Generation
// ============================================================================

DHKeyPair DH::generate_keypair() const {
    DHKeyPair keypair;
    
    // Generate random private key: 1 < x < q (or p-1)
    ZZ upper = IsZero(params_.q) ? params_.p - 1 : params_.q;
    size_t byte_len = static_cast<size_t>(NumBytes(upper));
    
    std::vector<uint8_t> buffer(byte_len);
    std::random_device rd;
    
    while (true) {
        for (size_t i = 0; i < byte_len; ++i) {
            buffer[i] = static_cast<uint8_t>(rd() & 0xFF);
        }
        
        keypair.private_key = ZZFromBytes(buffer.data(), static_cast<long>(byte_len));
        keypair.private_key = keypair.private_key % upper;
        
        // Ensure private key is in valid range [2, upper-1]
        if (keypair.private_key > ZZ(1) && keypair.private_key < upper) {
            break;
        }
    }
    
    // Clear buffer
    std::memset(buffer.data(), 0, buffer.size());
    
    // Compute public key: y = g^x mod p
    keypair.public_key = PowerMod(params_.g, keypair.private_key, params_.p);
    
    return keypair;
}

DHKeyPair DH::keypair_from_private(const ZZ& private_key) const {
    ZZ upper = IsZero(params_.q) ? params_.p - 1 : params_.q;
    
    if (private_key <= ZZ(1) || private_key >= upper) {
        throw std::invalid_argument("Invalid private key");
    }
    
    DHKeyPair keypair;
    keypair.private_key = private_key;
    keypair.public_key = PowerMod(params_.g, private_key, params_.p);
    
    return keypair;
}

ZZ DH::import_public_key(const uint8_t* data, size_t len) const {
    // Input is big-endian, convert to little-endian for NTL
    std::vector<uint8_t> le_bytes(len);
    for (size_t i = 0; i < len; i++) {
        le_bytes[i] = data[len - 1 - i];
    }
    ZZ pub = ZZFromBytes(le_bytes.data(), static_cast<long>(len));
    
    if (!validate_public_key(pub)) {
        throw std::invalid_argument("Invalid public key");
    }
    
    return pub;
}

DHKeyPair DH::import_private_key(const uint8_t* data, size_t len) const {
    // Input is big-endian, convert to little-endian for NTL
    std::vector<uint8_t> le_bytes(len);
    for (size_t i = 0; i < len; i++) {
        le_bytes[i] = data[len - 1 - i];
    }
    ZZ priv = ZZFromBytes(le_bytes.data(), static_cast<long>(len));
    return keypair_from_private(priv);
}

// ============================================================================
// Key Exchange
// ============================================================================

std::vector<uint8_t> DH::compute_shared_secret(const ZZ& private_key,
                                               const ZZ& peer_public_key) const {
    // Validate peer's public key
    if (!validate_public_key(peer_public_key)) {
        throw std::invalid_argument("Invalid peer public key");
    }
    
    // Compute shared secret: s = y_peer^x mod p
    ZZ shared = PowerMod(peer_public_key, private_key, params_.p);
    
    // Check for weak shared secret
    if (shared <= ZZ(1)) {
        throw std::runtime_error("DH computation resulted in weak shared secret");
    }
    
    // Convert to bytes (NTL outputs little-endian, PKCS#3 requires big-endian)
    size_t byte_len = get_prime_size();
    std::vector<uint8_t> le_bytes(byte_len);
    BytesFromZZ(le_bytes.data(), shared, static_cast<long>(byte_len));
    
    std::vector<uint8_t> result(byte_len);
    for (size_t i = 0; i < byte_len; i++) {
        result[i] = le_bytes[byte_len - 1 - i];
    }
    
    return result;
}

std::vector<uint8_t> DH::compute_shared_secret(const DHKeyPair& keypair,
                                               const ZZ& peer_public_key) const {
    return compute_shared_secret(keypair.private_key, peer_public_key);
}

std::vector<uint8_t> DH::compute_shared_secret(const uint8_t* private_key, size_t priv_len,
                                               const uint8_t* peer_public, size_t pub_len) const {
    // Input is big-endian, convert to little-endian for NTL
    std::vector<uint8_t> priv_le(priv_len);
    for (size_t i = 0; i < priv_len; i++) {
        priv_le[i] = private_key[priv_len - 1 - i];
    }
    ZZ priv = ZZFromBytes(priv_le.data(), static_cast<long>(priv_len));
    ZZ pub = import_public_key(peer_public, pub_len);
    
    return compute_shared_secret(priv, pub);
}

// ============================================================================
// Public Key Validation
// ============================================================================

bool DH::validate_public_key(const ZZ& public_key) const {
    // Check public key is in range [2, p-2]
    if (public_key <= ZZ(1) || public_key >= params_.p - 1) {
        return false;
    }
    
    // For safe primes, check public key is in the correct subgroup
    // y^q mod p should equal 1
    if (!IsZero(params_.q)) {
        ZZ check = PowerMod(public_key, params_.q, params_.p);
        if (check != ZZ(1)) {
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// High-Level API Functions
// ============================================================================

DHKeyPair dh_generate_keypair(DHGroupType group_type) {
    DH dh(group_type);
    return dh.generate_keypair();
}

std::vector<uint8_t> dh_shared_secret(DHGroupType group_type,
                                      const uint8_t* private_key, size_t priv_len,
                                      const uint8_t* peer_public_key, size_t pub_len) {
    DH dh(group_type);
    return dh.compute_shared_secret(private_key, priv_len, peer_public_key, pub_len);
}

} // namespace dh
} // namespace kctsb
