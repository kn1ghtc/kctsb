/**
 * @file test_rsa.cpp
 * @brief RSA OAEP/PSS Wycheproof vectors (SHA-256, 3072-bit)
 *
 * Uses standard Wycheproof vectors for RSAES-OAEP and RSASSA-PSS.
 * Only RSA-3072/4096 are supported by kctsb; vectors cover RSA-3072.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "kctsb/crypto/sha256.h"
#include "kctsb/kctsb_api.h"

namespace {

constexpr const char kModulusHex[] = R"HEX(
00c6fe23792566023c265287c5ac6f71541c0994d11d059ee6403986efa21c24
b51bd91d8862f9df79a4e328e3e27c83df260b25a9b43420affc44b51e8d7525
b6f29c372a405104732007527a62ed82fac73f4892a80e09682a41a58cd347017
f3be7d801334f92d9321aafd53b51bffabfc752cfccae0b1ee03bdaff9e428cc
1c117f1ac96b4fe23f8c23e6381186a66fd59289339ae55c4bcdadbff84abdaa
532240d4e1d28b2d0481dadd3b246557ca8fe18092817730b39e6ee378ffcc85
b19ffdc916a9b991a6b66d4a9c7bab5f5e7a3722101142e7a4108c15d573b152
89e07e46eaea07b42c2abcba330e99554b4656165bb4c0db2b6393a07eca575c
51a93c4e15bdb0f747909447e3efe34c67ca8954b530e56a20a1b6d84d45ed1b
cd3aa58ec06f184ee5857aaa819e1cca9a26f4e28d6b977d33916db9896d252d
1afa762e287cb0d384cc75bfe53f4e922d02dd0a481c042e2d306b4b3c189371
e575b25e0005a164cf69dd0976e4d5be476806ea6be6084e71ab4f5ac5c1b1203
)HEX";

constexpr const char kPublicExponentHex[] = "010001";

constexpr const char kPrivateExponentHex[] = R"HEX(
0f2d59fa46f271503222104df0d96d1cdba8956b9f998aa588177b25b2c90fb9
aa7e94448f3bfca1f404095ddc2be008f887581f89e981e6ba48694203cb000d
e4922a98f3dfda0587d75720938406fde68d7a9508f14d215f3bb38b3aa00b4a
af807ed69499c89afd39d0d86416579ca1dceb8182dc7167b0f58fbdf84d9e1b
b70502ff455d5796d9c5c2e966f2bc46cfa2e9b7d4e9e98bc055b6fad59d1fe78
29c0251c7628fc4d8033f7b4a7917d312b69291bc3791a4350dda746d6c7bc168
7b5fda19e481e85e94af5187acf34a805507cf44c51843ad6b680d492d921f69
25f2db860b06e495283479fdff8bf5fe07f2e47287fe0eac0dddfa24aa6e1f6e
49863a7bff1e4c2a4df05517a378a9a93e8f0f3090af3e9a8512bf456c03de16f
15dcdea48991c47a92cbb2f3dd230f3bf251f71b6e6e58966eff45a0568bcc93
e246fb5deee3b8c201438fd67643f312f46361a26fe538a12456d65e8941ccf71
0fc78b84c030ab4411bec06bb08c2aa12a1c4c1aa229a09a043b02cb6515
)HEX";

constexpr const char kOaepCt1Hex[] = R"HEX(
b47525feffb063be5201aaa1d6846f9f397589b988fa26848afb9bbd9d6b0d0c
92cec327332f02bd072d53e479726faff5fb89677c4947d60d5f1d7f3bbf2117
55975e1851f17f0d88eb970bd14719a9e5b257cde71071915774578e0bead5f7
ccd7b476732a47e0d54ef214488d733c689238f6cccd6c8be7145e0dee871fcb
b504c93e1efd842b228d67fa3e303a1081e26052c6c11ca85355a2de7f717dc4
32a90092ff9d3d75301e7f092b3b425354939c43f0879768342242836030822c
9bbbbe09d5e938fd070aac9f974c35dd46599766ac6f0f87a036a36e3650f724
4a336bee4a9ed1280b8adf57d702844c739354eae88ceabd8e66338e59262ecf
51b28f4dfe7bea8449383c27580f81ea06bb4bd031826e6f6ddd0c6a3c7eae23
d3d6acd5f6388fd9fa70e66c86d178394953ba4e391629a9a588797e25acf8c1
30859cb7c9504998cce6dd9e032b1a09aba8b215b03b4343a5c0f2a8253b5543
d301bd883e941786371bdad14117fa273296b153bca8ce4581df09fee1bd5e15
)HEX";

constexpr const char kOaepCtLabelHex[] = R"HEX(
7a9f4a75375002889bb9c4cafe5f044e2f28997474465251246788e51b0cd5c5
2c809a69f1ccef4c11723af030fb698a641b98b88b39c152e741b8ee29b13857
ec144f200c669010a657441701e929ed7df195669197f46909acc69388128bb7
5645f270f20df256f0d0c0ed488efcf26c44e4d4e54a8757f6c5bc7008c68b7f
ec43778743a76a890d383e2983a754095224c56862b4b62e20f112d1bd96f30a
3e66a20b01069c0ed9730f9f7de6cb13e2272640ca5cf807e64f44297e3e58ee
9331e1f04610694a0d5be7006f96747cf730ff3fc4bf8884b3f9f0cba9c4a8f3
8a01b225b083d77516d46ade258242b0ea4f367bcdff490e2f127f013808cfee
d451aa7c0f64b3156fc968507ec7c80572693d154b924fe18dfea946d52da81a
5ad0bfb5fac7010ed5b4f18a0bd1ef400a2804b9ca2b2dd0bb8b8b402952949b
ba935b674c4863ea4a9e38dd701d23c71e29b4a7c695856db5978b7e3c964ad8
fd4decb1cb5eb3f83e8ef0be4e5fefd27f8604b1d6fa06dd4f97110317bb19d9
)HEX";

constexpr const char kOaepCtInvalidHex[] = R"HEX(
5e6a85d2e4ebae323cdf919e12ac8e5028e0bd12501c5c81f2a30daa39a0ce15
ed25e705c59edab7e53895e9a4b60b0a0c75f11d984a5cdc45d8f300398868c7
6c973e5d47f50831cbe994c5c76633574bde9f274bde95f5f4c7a05c7c74f597
18e152c182b4dc9f86ec3a677d824ac63d33aa5dfd7d695bc409a3f22d84b4d7
5effa7c80b64647b1344e948087aecbbfbc607b667611fd7c3f847ce223d0ce6
ee131f75eee01cad17131b5de821fa7d6b458cf989e3005ecf6fcd1f6cd02216
2c2963e05893912cdfa9b06634ae0e040a73284414a9a6d8f8ac2e23b51ddcb1
08586216bcee3f07c7b1abc84c41b98cede33d5c4ab8f8259aa0c52a4b6cbb75
4aa21c2b2ebe83962039651c9159ec65da43458f6ff397d9503d41ee102d0456
ec58b1b8e28febdba82dc92e5e6941a097c8e406559f8410974fafbb77a9f72b
0566bde813306b1a7df7603f731e8982f1730b95f9e541b29eed40fa85978044
067650c55ead01240e58c456d9416145b0124170f10675e22d32920e91c11784
)HEX";

constexpr const char kPssSig1Hex[] = R"HEX(
b520065682633ba54c9b713b2ef19cdc1fcf275ba1744c2350da7307a20971cc
30eefa37d1667d23d20001a674f0e00df4f9b9e1d5fe7eb85cc45cab5dd62575
9de83017995c93d48b126df03aa74ef87daea0c1652dd370ad5d663598a383ca
c217a208b22c7cf0e448cc7ae0555f892ccb8ded6894cfb0c328cb542be0485d
860ca77203081f3b04c6f55c5689b1a66b1c24819a4a7ea55f32e00f61accf4b
411bb320a96c990173b63ccd74e7da7df5ceaf33a39a8acb89a845a594b164ec
6e22cce940eb06f2d487a8bc4574451878c2bbf57d241f76586e0703bf5f86be
e832d05b75fabaed6accadfc1ec2cd6e619dbb29b65d6e6f5e118ad52d82a955
d21005ecd63fb382f32bb8e2e1e57220b345cd6422bdd84a91495d0ab5775b08
139edee960dab1b4ffd9ea5b27398b58e6e35211c3581501e99bf5e3f17fd793
81528d28a4927e28082f45bfa9519f98ea663dc84c50317adf0bd5da98b01459
011cec61800534dd5afc5a567c19e4a400f06dee74112083b5322615c144ce3b
)HEX";

constexpr const char kPssSig2Hex[] = R"HEX(
8e10f23f49011d761946b283d7152e851ee76e5caa1741b0901eea317d8945f2
a0368551b3f2b3a6a0d6a939aebded8fea0a96dd1d037be33b1c35ce78dc89693
918a99d547a1d892f4047c09fff7a6523acb0cb0cddebcd4a6fdcc309a466ca9
580fedf032bf56154f8d79d5c4686abfd2c7abd342b37e5373b59a07fa865b11
8c44f2c44b851306dc97eaeeb638f14bafbb09c81996beabaaec28c19f06ffd5
9dbe3080e0124e2386418052735f541d496322c03ebee6e4dcaba24dde9772a9
f079973df26e854c255eb48df50c01d49831e54b64d0ff862d03fb4d82ff204d
303b537176c50ea56761a83d0aed8ed2deecbbba981c8aacd1300051a864d1ef
dc897f31383ccd6f181bf976a75e7a7613b60b3cb2a6f7ab8636f672990c1301
7f2981c11ba36096cbea898f016c581ee859e950bec195cc4e376e134341b2fd
3e3d6181ba4d377b2aab6a148c6ea8cca9ee3478297e901856ab18f61c0233c8
99841e5da125516cf5274dc1b22e2a51c922daeeccfad0f2a8bf84e531bc4f8
)HEX";

constexpr const char kPssSigInvalidHex[] = R"HEX(
730a26b2c3fc2df474212c04fcb346b3b78a58c611351871ac1c5262867ce19a
6f553880d68ba4c35827610b72bb044162b083fe9ffa7a82e236609046482194
6f2ce1a8ea19b12c10c0e42a52ff805851c226748a9d65d7cb2057c9ee0beddd
8ca02ae1bc36ced39925d2429d531c2e607bfbf0648708ef4f7d816c8839cc8c
62036ac37e811f94a943198acf6e19c66cd829bde9dec9969eb4724e2d4ddc4f
8c2bb2527007ddbaf2975937ece7f1779db28c610503e7ebbf0b03459a1f4794
136842b57d04f14e22b98ef37939c64d08fb242cca548b7bb2c2d8b1df6bb8b0
b7f6f38e47226e9fc0a4723c2a518ebdc5c4c8f15db74fe958bb567e55f092d3
dc8af0128b353e2d273d574433c22cca579c479005b52c715eff1ef4eca8d82d
2f6d7cc972fe0e75f19eeea3b77ea7fe26b1d29cedbfa7ef0737e4aa50a567b5
fb417e356fa8034a72a53c5d1c0cd467808df6faeba89dddeaeb09c3ce793745
0b41e7c1d4403b3033d3531adc24e9f5fe35d877a3e36fd3702289e69b460b97
)HEX";

struct OaepVector {
    const char* msg_hex;
    const char* ct_hex;
    const char* label_hex;
    bool valid;
};

struct PssVector {
    const char* msg_hex;
    const char* sig_hex;
    bool valid;
};

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

std::vector<uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<uint8_t> out;
    int high = -1;
    for (char c : hex) {
        if (std::isspace(static_cast<unsigned char>(c)) != 0) {
            continue;
        }
        int value = hex_value(c);
        if (value < 0) {
            throw std::invalid_argument("invalid hex");
        }
        if (high < 0) {
            high = value;
        } else {
            out.push_back(static_cast<uint8_t>((high << 4) | value));
            high = -1;
        }
    }
    if (high >= 0) {
        throw std::invalid_argument("odd hex length");
    }
    return out;
}

std::vector<uint8_t> normalize_length(std::vector<uint8_t> bytes, size_t expected_len) {
    while (bytes.size() > expected_len && !bytes.empty() && bytes.front() == 0) {
        bytes.erase(bytes.begin());
    }
    if (bytes.size() > expected_len) {
        throw std::invalid_argument("hex too long");
    }
    if (bytes.size() < expected_len) {
        std::vector<uint8_t> padded(expected_len - bytes.size(), 0);
        padded.insert(padded.end(), bytes.begin(), bytes.end());
        return padded;
    }
    return bytes;
}

const uint8_t* non_null_or_dummy(const std::vector<uint8_t>& data, uint8_t& dummy) {
    if (!data.empty()) {
        return data.data();
    }
    dummy = 0;
    return &dummy;
}

}  // namespace

class RsaWycheproofTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        std::vector<uint8_t> n = normalize_length(hex_to_bytes(kModulusHex),
            KCTSB_RSA_3072_BYTES);
        std::vector<uint8_t> e = hex_to_bytes(kPublicExponentHex);
        std::vector<uint8_t> d = normalize_length(hex_to_bytes(kPrivateExponentHex),
            KCTSB_RSA_3072_BYTES);

        ASSERT_EQ(kctsb_rsa_public_key_init(&pub_, n.data(), n.size(), e.data(), e.size()),
            KCTSB_SUCCESS);
        ASSERT_EQ(kctsb_rsa_private_key_init(&priv_, n.data(), n.size(), d.data(), d.size()),
            KCTSB_SUCCESS);
    }

    static kctsb_rsa_public_key_t pub_;
    static kctsb_rsa_private_key_t priv_;
};

kctsb_rsa_public_key_t RsaWycheproofTest::pub_{};
kctsb_rsa_private_key_t RsaWycheproofTest::priv_{};

TEST_F(RsaWycheproofTest, OaepDecryptVectors) {
    const OaepVector vectors[] = {
        { "", kOaepCt1Hex, "", true },
        { "313233343030", kOaepCtLabelHex, "0000000000000000", true },
        { "313233343030", kOaepCtInvalidHex, "", false },
    };

    for (const auto& vec : vectors) {
        std::vector<uint8_t> msg = hex_to_bytes(vec.msg_hex);
        std::vector<uint8_t> ct = hex_to_bytes(vec.ct_hex);
        if (!ct.empty()) {
            ct = normalize_length(std::move(ct), pub_.n_len);
        }
        std::vector<uint8_t> label = hex_to_bytes(vec.label_hex);

        std::vector<uint8_t> out(pub_.n_len, 0);
        size_t out_len = out.size();
        uint8_t dummy_label = 0;
        const uint8_t* label_ptr = non_null_or_dummy(label, dummy_label);

        kctsb_error_t rc = kctsb_rsa_oaep_decrypt_sha256(
            &priv_,
            ct.data(),
            ct.size(),
            label_ptr,
            label.size(),
            out.data(),
            &out_len);

        if (vec.valid) {
            ASSERT_EQ(rc, KCTSB_SUCCESS);
            ASSERT_EQ(out_len, msg.size());
            EXPECT_EQ(0, std::memcmp(out.data(), msg.data(), msg.size()));
        } else {
            EXPECT_NE(rc, KCTSB_SUCCESS);
        }
    }
}

TEST_F(RsaWycheproofTest, PssVerifyVectors) {
    const PssVector vectors[] = {
        { "", kPssSig1Hex, true },
        { "0000000000000000000000000000000000000000", kPssSig2Hex, true },
        { "313233343030", kPssSigInvalidHex, false },
    };

    for (const auto& vec : vectors) {
        std::vector<uint8_t> msg = hex_to_bytes(vec.msg_hex);
        std::vector<uint8_t> sig = normalize_length(hex_to_bytes(vec.sig_hex), pub_.n_len);
        std::array<uint8_t, KCTSB_SHA256_DIGEST_SIZE> hash{};
        uint8_t dummy_msg = 0;
        const uint8_t* msg_ptr = non_null_or_dummy(msg, dummy_msg);
        kctsb_sha256(msg_ptr, msg.size(), hash.data());

        kctsb_error_t rc = kctsb_rsa_pss_verify_sha256(
            &pub_, hash.data(), hash.size(), sig.data(), sig.size());

        if (vec.valid) {
            EXPECT_EQ(rc, KCTSB_SUCCESS);
        } else {
            EXPECT_NE(rc, KCTSB_SUCCESS);
        }
    }
}
