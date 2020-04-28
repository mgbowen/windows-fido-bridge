#pragma once

#include <cstdint>

namespace wfb {

constexpr const uint8_t CBOR_NON_NEGATIVE_INTEGER = 0;
constexpr const uint8_t CBOR_NEGATIVE_INTEGER = 1;
constexpr const uint8_t CBOR_BYTE_STRING = 2;
constexpr const uint8_t CBOR_TEXT_STRING = 3;
constexpr const uint8_t CBOR_ARRAY = 4;
constexpr const uint8_t CBOR_MAP = 5;

class binary_reader;

uint64_t read_raw_length(binary_reader& reader);

}  // namespace wfb
