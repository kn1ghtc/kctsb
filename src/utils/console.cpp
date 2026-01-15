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
    // Set console code page to UTF-8 for proper Unicode display
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Enable UTF-8 text mode for streams (NOT binary mode)
    // Using _O_U8TEXT causes issues with narrow strings, so we use _O_TEXT
    // The combination of CP_UTF8 + _O_TEXT ensures proper display
    _setmode(_fileno(stdout), _O_TEXT);
    _setmode(_fileno(stderr), _O_TEXT);

    // Enable ANSI escape sequences for modern Windows terminals
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif

    // Use classic locale for consistent behavior with UTF-8 console
    // Avoid locale-specific number formatting that can cause display issues
    std::locale::global(std::locale::classic());
    std::cout.imbue(std::locale::classic());
    std::cerr.imbue(std::locale::classic());

    // Sync with C stdio for consistent output ordering
    std::ios::sync_with_stdio(true);
}

} // namespace utils
} // namespace kctsb
