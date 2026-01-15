#include <iostream>
#include <iomanip>
#include <cstring>
#include <NTL/ZZ.h>

using namespace NTL;

void print_hex(const uint8_t* data, size_t len, const char* label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::endl;
}

ZZ bytes_to_zz(const uint8_t* data, size_t len) {
    ZZ result = ZZ(0);
    for (size_t i = 0; i < len; i++) {
        result <<= 8;
        result += data[i];
    }
    return result;
}

void zz_to_bytes(const ZZ& z, uint8_t* out, size_t len) {
    std::memset(out, 0, len);
    uint8_t* tmp = new uint8_t[len];
    BytesFromZZ(tmp, z, (long)len);
    // Reverse to big-endian
    for (size_t i = 0; i < len; i++) {
        out[i] = tmp[len - 1 - i];
    }
    delete[] tmp;
}

int main() {
    // Test vector (SM2 Gx coordinate)
    uint8_t test[] = {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 
        0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94, 
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
    };
    
    print_hex(test, 32, "Original");
    
    ZZ z = bytes_to_zz(test, 32);
    std::cout << "ZZ value: " << z << std::endl;
    
    uint8_t recovered[32];
    zz_to_bytes(z, recovered, 32);
    print_hex(recovered, 32, "Recovered");
    
    bool match = (std::memcmp(test, recovered, 32) == 0);
    std::cout << "Match: " << (match ? "YES" : "NO") << std::endl;
    
    return 0;
}
