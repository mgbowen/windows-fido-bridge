#pragma once

#include <cstdint>
#include <tuple>

namespace wfb {

constexpr const uint8_t CBOR_NON_NEGATIVE_INTEGER = 0;
constexpr const uint8_t CBOR_NEGATIVE_INTEGER = 1;
constexpr const uint8_t CBOR_BYTE_STRING = 2;
constexpr const uint8_t CBOR_TEXT_STRING = 3;
constexpr const uint8_t CBOR_ARRAY = 4;
constexpr const uint8_t CBOR_MAP = 5;
constexpr const uint8_t CBOR_EVERYTHING_ELSE = 7;

constexpr const uint8_t CBOR_VALUE_NULL = 22;

class binary_reader;
class binary_writer;

std::tuple<uint8_t, uint64_t> read_raw_length(binary_reader& reader);
void write_initial_byte_into(binary_writer& writer, uint8_t major_type, uint64_t raw_value);

}  // namespace wfb
