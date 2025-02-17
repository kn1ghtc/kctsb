//
//  tlsstruct.h
//  kcalg
//
//  Created by knightc on 2019/4/22.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef tlsstruct_h
#define tlsstruct_h

//B.1. Record Layer
enum {
    invalid(0),
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    heartbeat(24), /* RFC 6520 */
    (255)
} ContentType;
struct {
    ContentType type;
    ProtocolVersion legacy_record_version;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
struct {
    opaque content[TLSPlaintext.length];
    ContentType type;
    uint8 zeros[length_of_padding];
} TLSInnerPlaintext;
struct {
    ContentType opaque_type = application_data; /* 23 */
    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    uint16 length;
    opaque encrypted_record[TLSCiphertext.length];
} TLSCiphertext;

//B.2. Alert Messages
enum { warning(1), fatal(2), (255) } AlertLevel;
enum {
    close_notify(0),
    unexpected_message(10),
    bad_record_mac(20),
    decryption_failed_RESERVED(21),
    record_overflow(22),
    decompression_failure_RESERVED(30),
    handshake_failure(40),
    no_certificate_RESERVED(41),
    bad_certificate(42),
    unsupported_certificate(43),
    certificate_revoked(44),
    certificate_expired(45),
    certificate_unknown(46),
    illegal_parameter(47),
    unknown_ca(48),
    access_denied(49),
    decode_error(50),
    decrypt_error(51),
    export_restriction_RESERVED(60),
    protocol_version(70),
    insufficient_security(71),
    internal_error(80),
    inappropriate_fallback(86),
    user_canceled(90),
    no_renegotiation_RESERVED(100),
    missing_extension(109),
    unsupported_extension(110),
    certificate_unobtainable_RESERVED(111),
    unrecognized_name(112),
    bad_certificate_status_response(113),
    bad_certificate_hash_value_RESERVED(114),
    unknown_psk_identity(115),
    certificate_required(116),
    no_application_protocol(120),
    (255)
} AlertDescription;
struct {
    AlertLevel level;
    AlertDescription description;
} Alert;

//B.3. Handshake Protocol
enum {
    hello_request_RESERVED(0),
    client_hello(1),
    server_hello(2),
    hello_verify_request_RESERVED(3),
    new_session_ticket(4),
    end_of_early_data(5),
    hello_retry_request_RESERVED(6),
    encrypted_extensions(8),
    certificate(11),
    server_key_exchange_RESERVED(12),
    certificate_request(13),
    server_hello_done_RESERVED(14),
    certificate_verify(15),
    client_key_exchange_RESERVED(16),
    finished(20),
    certificate_url_RESERVED(21),
    certificate_status_RESERVED(22),
    supplemental_data_RESERVED(23),
    key_update(24),
    message_hash(254),
    (255)
} HandshakeType;
struct {
    HandshakeType msg_type; /* handshake type */
    uint24 length; /* bytes in message */
    select (Handshake.msg_type) {
    case client_hello: ClientHello;
    case server_hello: ServerHello;
    case end_of_early_data: EndOfEarlyData;
    case encrypted_extensions: EncryptedExtensions;
    case certificate_request: CertificateRequest;
    case certificate: Certificate;
    case certificate_verify: CertificateVerify;
    case finished: Finished;
    case new_session_ticket: NewSessionTicket;
    case key_update: KeyUpdate;
    };
} Handshake;

//B.3.1. Key Exchange Messages
uint16 ProtocolVersion;
opaque Random[32];
uint8 CipherSuite[2]; /* Cryptographic suite selector */
struct {
    ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
} ClientHello;
struct {
    ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
    Random random;
    opaque legacy_session_id_echo<0..32>;
    CipherSuite cipher_suite;
    uint8 legacy_compression_method = 0;
    Extension extensions<6..2^16-1>;
} ServerHello;
struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;
enum {
    server_name(0), /* RFC 6066 */
    max_fragment_length(1), /* RFC 6066 */
    status_request(5), /* RFC 6066 */
    supported_groups(10), /* RFC 8422, 7919 */
    signature_algorithms(13), /* RFC 8446 */
    use_srtp(14), /* RFC 5764 */
    heartbeat(15), /* RFC 6520 */
    application_layer_protocol_negotiation(16), /* RFC 7301 */
    signed_certificate_timestamp(18), /* RFC 6962 */
    client_certificate_type(19), /* RFC 7250 */
    server_certificate_type(20), /* RFC 7250 */
    padding(21), /* RFC 7685 */
    RESERVED(40), /* Used but never
                   assigned */
    pre_shared_key(41), /* RFC 8446 */
    early_data(42), /* RFC 8446 */
    supported_versions(43), /* RFC 8446 */
    cookie(44), /* RFC 8446 */
    psk_key_exchange_modes(45), /* RFC 8446 */
    RESERVED(46), /* Used but never
                   assigned */
    certificate_authorities(47), /* RFC 8446 */
    oid_filters(48), /* RFC 8446 */
    post_handshake_auth(49), /* RFC 8446 */
    signature_algorithms_cert(50), /* RFC 8446 */
    key_share(51), /* RFC 8446 */
    (65535)
} ExtensionType;
struct {
    NamedGroup group;
    opaque key_exchange<1..2^16-1>;
} KeyShareEntry;
struct {
    KeyShareEntry client_shares<0..2^16-1>;
} KeyShareClientHello;
struct {
    NamedGroup selected_group;
} KeyShareHelloRetryRequest;

struct {
    KeyShareEntry server_share;
} KeyShareServerHello;
struct {
    uint8 legacy_form = 4;
    opaque X[coordinate_length];
    opaque Y[coordinate_length];
} UncompressedPointRepresentation;
enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
struct {
    PskKeyExchangeMode ke_modes<1..255>;
} PskKeyExchangeModes;
struct {} Empty;
struct {
    select (Handshake.msg_type) {
    case new_session_ticket: uint32 max_early_data_size;
    case client_hello: Empty;
    case encrypted_extensions: Empty;
    };
} EarlyDataIndication;
struct {
    opaque identity<1..2^16-1>;
    uint32 obfuscated_ticket_age;
} PskIdentity;
opaque PskBinderEntry<32..255>;
struct {
    PskIdentity identities<7..2^16-1>;
    PskBinderEntry binders<33..2^16-1>;
} OfferedPsks;
struct {
    select (Handshake.msg_type) {
    case client_hello: OfferedPsks;
    case server_hello: uint16 selected_identity;
    };
} PreSharedKeyExtension;

//B.3.1.1. Version Extension
struct {
    select (Handshake.msg_type) {
    case client_hello:
        ProtocolVersion versions<2..254>;
    case server_hello: /* and HelloRetryRequest */
        ProtocolVersion selected_version;
    };
} SupportedVersions;

//B.3.1.2. Cookie Extension
struct {
    opaque cookie<1..2^16-1>;
} Cookie;

//B.3.1.3. Signature Algorithm Extension
enum {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256(0x0401),
    rsa_pkcs1_sha384(0x0501),
    rsa_pkcs1_sha512(0x0601),
    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256(0x0403),
    ecdsa_secp384r1_sha384(0x0503),
    ecdsa_secp521r1_sha512(0x0603),
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256(0x0804),
    rsa_pss_rsae_sha384(0x0805),
    rsa_pss_rsae_sha512(0x0806),
    /* EdDSA algorithms */
    ed25519(0x0807),
    ed448(0x0808),
    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256(0x0809),
    rsa_pss_pss_sha384(0x080a),
    rsa_pss_pss_sha512(0x080b),
    /* Legacy algorithms */
    rsa_pkcs1_sha1(0x0201),
    ecdsa_sha1(0x0203),
    /* Reserved Code Points */
    obsolete_RESERVED(0x0000..0x0200),
    dsa_sha1_RESERVED(0x0202),
    obsolete_RESERVED(0x0204..0x0400),
    dsa_sha256_RESERVED(0x0402),
    obsolete_RESERVED(0x0404..0x0500),
    dsa_sha384_RESERVED(0x0502),
    obsolete_RESERVED(0x0504..0x0600),
    dsa_sha512_RESERVED(0x0602),
    obsolete_RESERVED(0x0604..0x06FF),
    private_use(0xFE00..0xFFFF),
    (0xFFFF)
} SignatureScheme;
struct {
    SignatureScheme supported_signature_algorithms<2..2^16-2>;
} SignatureSchemeList;

//B.3.1.4. Supported Groups Extension
enum {
    unallocated_RESERVED(0x0000),
    /* Elliptic Curve Groups (ECDHE) */
    obsolete_RESERVED(0x0001..0x0016),
    secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
    obsolete_RESERVED(0x001A..0x001C),
    x25519(0x001D), x448(0x001E),
    /* Finite Field Groups (DHE) */
    ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
    ffdhe6144(0x0103), ffdhe8192(0x0104),
    /* Reserved Code Points */
    ffdhe_private_use(0x01FC..0x01FF),
    ecdhe_private_use(0xFE00..0xFEFF),
    obsolete_RESERVED(0xFF01..0xFF02),
    (0xFFFF)
} NamedGroup;
struct {
    NamedGroup named_group_list<2..2^16-1>;
} NamedGroupList;

//B.3.2. Server Parameters Messages
opaque DistinguishedName<1..2^16-1>;
struct {
    DistinguishedName authorities<3..2^16-1>;
} CertificateAuthoritiesExtension;
struct {
    opaque certificate_extension_oid<1..2^8-1>;
    opaque certificate_extension_values<0..2^16-1>;
} OIDFilter;
struct {
    OIDFilter filters<0..2^16-1>;
} OIDFilterExtension;
struct {} PostHandshakeAuth;
struct {
    Extension extensions<0..2^16-1>;
} EncryptedExtensions;
struct {
    opaque certificate_request_context<0..2^8-1>;
    Extension extensions<2..2^16-1>;
} CertificateRequest;

//B.3.3. Authentication Messages
enum {
    X509(0),
    OpenPGP_RESERVED(1),
    RawPublicKey(2),
    (255)
} CertificateType;
struct {
    select (certificate_type) {
    case RawPublicKey:
        /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
        opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
    case X509:
        opaque cert_data<1..2^24-1>;
    };
    Extension extensions<0..2^16-1>;
} CertificateEntry;
struct {
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;
} Certificate;
struct {
    SignatureScheme algorithm;
    opaque signature<0..2^16-1>;
} CertificateVerify;
struct {
    opaque verify_data[Hash.length];
} Finished;

//B.3.4. Ticket Establishment
struct {
    uint32 ticket_lifetime;
    uint32 ticket_age_add;
    opaque ticket_nonce<0..255>;
    opaque ticket<1..2^16-1>;
    Extension extensions<0..2^16-2>;
} NewSessionTicket;

//B.3.5. Updating Keys
struct {} EndOfEarlyData;
enum {
    update_not_requested(0), update_requested(1), (255)
} KeyUpdateRequest;
struct {
    KeyUpdateRequest request_update;
} KeyUpdate;


#endif /* tlsstruct_h */
