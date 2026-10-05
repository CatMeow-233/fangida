#include "fangida_native.h"

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>

namespace {
void check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}
}

int main() {
    check(fangida_abi_version() == 0x10000, "ABI version");
    const uint8_t sample[] = {'X', 'X', 'X', 'X', 0, 'a', '"', '\\', 'b'};
    fangida_buffer result{};
    check(fangida_analyze(sample, sizeof sample, &result) == FANGIDA_OK, "analysis");
    const std::string json(reinterpret_cast<char *>(result.data), static_cast<size_t>(result.length));
    check(json.find("\"size\":9") != std::string::npos, "byte count");
    check(json.find("\"offset\":0,\"text\":\"XXXX\"") != std::string::npos, "first string");
    check(json.find("\"offset\":5,\"text\":\"a\\\"\\\\b\"") != std::string::npos, "escaped string");
    check(json.find("\"strings_truncated\":false") != std::string::npos, "truncation flag");
    fangida_release(&result);
    fangida_release(&result);
    check(result.data == nullptr && result.length == 0, "release reset");

    check(fangida_analyze(nullptr, 0, &result) == FANGIDA_OK, "empty input");
    fangida_release(&result);
    check(fangida_analyze(nullptr, 1, &result) == FANGIDA_INVALID, "null input");
    check(fangida_analyze(sample, FANGIDA_MAX_INPUT_BYTES + 1, &result) == FANGIDA_INVALID, "input cap");
    check(fangida_analyze(sample, sizeof sample, nullptr) == FANGIDA_INVALID, "null output");

    const std::string long_run(129, 'Q');
    check(fangida_analyze(reinterpret_cast<const uint8_t *>(long_run.data()), long_run.size(), &result) == FANGIDA_OK,
          "long string analysis");
    const std::string truncated(reinterpret_cast<char *>(result.data), static_cast<size_t>(result.length));
    check(truncated.find("\"strings_truncated\":true") != std::string::npos, "long string truncation");
    fangida_release(&result);
    return 0;
}
