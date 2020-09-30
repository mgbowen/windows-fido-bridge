#include "windows_fido_bridge/cbor/types/value.hpp"

#include <iostream>
#include <sstream>

namespace wfb {

void cbor_value::dump_cbor_into(binary_writer& writer) const {
    std::visit([&](auto&& value) { value.dump_cbor_into(writer); }, _storage);
}

void cbor_value::print_debug() const {
    std::stringstream ss;
    print_debug(ss);
    std::cerr << ss.str() << "\n";
}

void cbor_value::print_debug(std::stringstream& ss) const {
    std::visit([&](auto&& value) { value.print_debug(ss); }, _storage);
}

bool cbor_value::operator==(const cbor_value& rhs) const {
    return _storage == rhs._storage;
}

bool cbor_value::operator<(const cbor_value& rhs) const {
    return _storage < rhs._storage;
}

}  // namespace
