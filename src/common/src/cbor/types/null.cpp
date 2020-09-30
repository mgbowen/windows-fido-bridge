#include "windows_fido_bridge/cbor/types/null.hpp"

namespace wfb {

cbor_null::cbor_null() {}

void cbor_null::dump_cbor_into(binary_writer& writer) const {
    write_initial_byte_into(writer, CBOR_EVERYTHING_ELSE, CBOR_VALUE_NULL);
}

void cbor_null::print_debug() const {
    std::stringstream ss;
    print_debug(ss);
    std::cerr << ss.str() << "\n";
}

void cbor_null::print_debug(std::stringstream& ss) const {
    ss << "null";
}

bool cbor_null::operator==(const cbor_null& rhs) const {
    return true;
}

bool cbor_null::operator<(const cbor_null& rhs) const {
    return true;
}

}  // namespace wfb
