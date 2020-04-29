#include "windows_fido_bridge/cbor/parse.hpp"

#include "windows_fido_bridge/cbor/detail.hpp"
#include "windows_fido_bridge/cbor/types/value.hpp"

#include <windows_fido_bridge/binary_io.hpp>

#include <cstdint>

namespace wfb { namespace detail {

cbor_value parse_cbor_from_reader(binary_reader& reader) {
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
    }

    throw std::runtime_error("Unrecognized CBOR type {} at byte {}"_format(type, reader.index()));
}

}  // namespace detail
}  // namespace wfb
