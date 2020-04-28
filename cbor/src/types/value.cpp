#include "windows_fido_bridge/cbor/types/value.hpp"

#include <iostream>
#include <sstream>

namespace wfb {

void cbor_value::dump() const {
    std::stringstream ss;
    dump(ss);
    std::cerr << ss.str() << "\n";
}

void cbor_value::dump(std::stringstream& ss) const {
    std::visit([&](auto&& value) { value.dump(ss); }, _storage);
}

bool cbor_value::operator==(const cbor_value& rhs) const {
    return _storage == rhs._storage;
}

bool cbor_value::operator<(const cbor_value& rhs) const {
    return _storage < rhs._storage;
}

}  // namespace
