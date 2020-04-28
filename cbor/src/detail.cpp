#include "windows_fido_bridge/cbor/detail.hpp"
#include "windows_fido_bridge/cbor/types/integer.hpp"

#include <windows_fido_bridge/binary_io.hpp>

namespace wfb {

uint64_t read_raw_length(binary_reader& reader) {
    return cbor_integer{reader}.raw_value();
}

}  // namespace wfb
