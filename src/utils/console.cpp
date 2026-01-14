/**
 * @file console.cpp
 * @brief UTF-8 console configuration helpers implementation.
 */

#include "kctsb/utils/console.h"

#include <exception>
#include <iostream>
#include <locale>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

extern "C" void kctsb_enable_utf8_console(void) {
    kctsb::utils::enable_utf8_console();
}

namespace kctsb {
namespace utils {

void enable_utf8_console() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#endif

    try {
        std::locale utf8_locale("");
        std::locale::global(utf8_locale);
        std::cout.imbue(utf8_locale);
        std::cerr.imbue(utf8_locale);
    } catch (const std::exception&) {
        std::locale::global(std::locale::classic());
        std::cout.imbue(std::locale());
        std::cerr.imbue(std::locale());
    }

    std::ios::sync_with_stdio(false);
}

} // namespace utils
} // namespace kctsb
