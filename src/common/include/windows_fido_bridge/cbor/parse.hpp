#pragma once

#include <windows_fido_bridge/cbor/types/value.hpp>
#include <windows_fido_bridge/cbor/parse_fwd.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

#include <cstdint>
#include <type_traits>
#include <utility>

namespace wfb {

class binary_reader;
class cbor_value;

namespace detail {

template <typename TCborValue>
TCborValue parse_cbor_from_reader(binary_reader& reader) {
    // Read the first byte to determine the type
    uint8_t initial_byte = reader.peek_uint8_t();
    uint8_t type = initial_byte >> 5;

    switch (type) {
        case CBOR_NON_NEGATIVE_INTEGER:
        case CBOR_NEGATIVE_INTEGER: {
            return cbor_integer{reader};
        }
        case CBOR_BYTE_STRING: {
            return cbor_byte_string{reader};
        }
        case CBOR_TEXT_STRING: {
            return cbor_text_string{reader};
        }
        case CBOR_ARRAY: {
            return cbor_array{reader};
        }
        case CBOR_MAP: {
            return cbor_map{reader};
        }
        case CBOR_EVERYTHING_ELSE: {
            uint8_t value = initial_byte & 0b00011111;
            switch (value) {
                case CBOR_VALUE_NULL: {
                    reader.read_uint8_t();  // Consume the value
                    return cbor_null{};
                }
            }
        }
    }

    throw std::runtime_error("Unrecognized CBOR type {} at byte {}"_format(type, reader.index()));
}

}  // namespace detail

template <typename T, typename... Args, typename TCborValue>
T parse_cbor(Args&&... args) {
    binary_reader reader(std::forward<Args>(args)...);
    return static_cast<T>(detail::parse_cbor_from_reader<TCborValue>(reader));
}

template <typename T, typename TBinaryReader, typename TCborValue>
std::enable_if_t<std::is_same_v<remove_cvref_t<TBinaryReader>, binary_reader>, T>
parse_cbor(TBinaryReader&& reader) {
    return static_cast<T>(detail::parse_cbor_from_reader<TCborValue>(std::forward<TBinaryReader>(reader)));
}

}  // namespace wfb
