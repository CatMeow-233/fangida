#include "fangida_native.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
constexpr uint64_t kMinimumStringLength = 4;
constexpr uint64_t kMaximumStrings = 32;
constexpr uint64_t kMaximumStringLength = 128;

bool printable(uint8_t byte) noexcept { return byte >= 0x20 && byte <= 0x7e; }

void append_escaped(std::string &json, const uint8_t *data, uint64_t length) {
    for (uint64_t i = 0; i < length; ++i) {
        const char c = static_cast<char>(data[i]);
        if (c == '\\' || c == '"') json.push_back('\\');
        json.push_back(c);
    }
}

std::string analyze_json(const uint8_t *data, uint64_t length) {
    std::array<uint64_t, 256> histogram{};
    for (uint64_t i = 0; i < length; ++i) ++histogram[data[i]];

    std::string json = "{\"schema_version\":1,\"size\":";
    json += std::to_string(length);
    json += ",\"histogram\":[";
    for (size_t i = 0; i < histogram.size(); ++i) {
        if (i != 0) json.push_back(',');
        json += std::to_string(histogram[i]);
    }
    json += "],\"strings\":[";

    uint64_t found = 0;
    bool truncated = false;
    for (uint64_t i = 0; i < length;) {
        if (!printable(data[i])) {
            ++i;
            continue;
        }
        const uint64_t start = i;
        do { ++i; } while (i < length && printable(data[i]));
        const uint64_t run_length = i - start;
        if (run_length < kMinimumStringLength) continue;
        if (found >= kMaximumStrings) {
            truncated = true;
            continue;
        }
        if (found++ != 0) json.push_back(',');
        json += "{\"offset\":";
        json += std::to_string(start);
        json += ",\"text\":\"";
        const uint64_t kept = run_length < kMaximumStringLength ? run_length : kMaximumStringLength;
        append_escaped(json, data + start, kept);
        json += "\"}";
        if (run_length > kept) truncated = true;
    }
    json += truncated ? "],\"strings_truncated\":true}" : "],\"strings_truncated\":false}";
    return json;
}
} // namespace

extern "C" uint32_t fangida_abi_version(void) {
    return (FANGIDA_ABI_MAJOR << 16) | FANGIDA_ABI_MINOR;
}

extern "C" fangida_status fangida_analyze(const uint8_t *data, uint64_t length, fangida_buffer *out) {
    if (!out) return FANGIDA_INVALID;
    out->data = nullptr;
    out->length = 0;
    if (length > FANGIDA_MAX_INPUT_BYTES || (!data && length != 0)) return FANGIDA_INVALID;

    try {
        const std::string json = analyze_json(data, length);
        auto *result = static_cast<uint8_t *>(std::malloc(json.size()));
        if (!result) return FANGIDA_FAILED;
        std::memcpy(result, json.data(), json.size());
        out->data = result;
        out->length = static_cast<uint64_t>(json.size());
        return FANGIDA_OK;
    } catch (...) {
        return FANGIDA_FAILED;
    }
}

extern "C" void fangida_release(fangida_buffer *buffer) {
    if (!buffer) return;
    std::free(buffer->data);
    buffer->data = nullptr;
    buffer->length = 0;
}
