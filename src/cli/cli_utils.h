/**
 * @file cli_utils.h
 * @brief Common utility functions for kctsb CLI commands
 *
 * @author kctsb Development Team
 * @date 2026-01-13
 */

#ifndef KCTSB_CLI_UTILS_H
#define KCTSB_CLI_UTILS_H

#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace kctsb {
namespace cli {

/**
 * @brief Read file into byte vector
 */
inline std::vector<unsigned char> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open input file: " + filename);
    }
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

/**
 * @brief Write byte vector to file
 */
inline void write_file(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open output file: " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

/**
 * @brief Convert bytes to hex string
 */
inline std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

/**
 * @brief Convert hex string to bytes
 */
inline std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte = 0;
        std::istringstream iss(hex.substr(i, 2));
        iss >> std::hex >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}

} // namespace cli
} // namespace kctsb

#endif // KCTSB_CLI_UTILS_H
