#pragma once

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/types.hpp>

namespace wfb {

class cbor_value;

template <typename TCborValue>
byte_vector dump_cbor(const TCborValue& value) {
    binary_writer writer;
    value.dump_cbor_into(writer);
    return writer.vector();
}

}  // namespace wfb
