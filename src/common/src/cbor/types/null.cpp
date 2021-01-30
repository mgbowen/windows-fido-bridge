#include "windows_fido_bridge/cbor/types/null.hpp"

namespace wfb {

cbor_null::cbor_null() {}

void cbor_null::dump_cbor_into(binary_writer& writer) const {
    write_initial_byte_into(writer, CBOR_EVERYTHING_ELSE, CBOR_VALUE_NULL);
}

std::string cbor_null::dump_debug() const {
    std::stringstream ss;
    dump_debug(ss);
    return ss.str();
}

void cbor_null::dump_debug(std::stringstream& ss) const {
    ss << "(null)";
}

bool cbor_null::operator==(const cbor_null& rhs) const {
    return true;
}

bool cbor_null::operator<(const cbor_null& rhs) const {
    return true;
}

}  // namespace wfb
