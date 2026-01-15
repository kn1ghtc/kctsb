/**
 * @file console.h
 * @brief UTF-8 console configuration utilities for cross-platform binaries.
 *
 * Provides C and C++ helpers to force UTF-8 output on Windows consoles and
 * when stdout/stderr are redirected (e.g., `kctsb_benchmark.exe 2>&1`). On
 * non-Windows platforms this ensures the global locale follows the process
 * locale for consistent encoding behavior.
 */

#ifndef KCTSB_UTILS_CONSOLE_H
#define KCTSB_UTILS_CONSOLE_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enable UTF-8 console/stream output for C entry points.
 */
KCTSB_API void kctsb_enable_utf8_console(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <locale>

namespace kctsb {
namespace utils {

/**
 * @brief Configure stdout/stderr to emit UTF-8 safely across platforms.
 *
 * - On Windows: forces console code page to UTF-8 and switches stdout/stderr
 *   to binary mode to avoid code-page mangling when redirection is used.
 * - All platforms: sets the global locale to the user locale if available and
 *   imbues iostreams for consistent Unicode handling.
 */
void enable_utf8_console();

} // namespace utils
} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_UTILS_CONSOLE_H