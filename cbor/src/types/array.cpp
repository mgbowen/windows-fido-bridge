#include "windows_fido_bridge/cbor/types/array.hpp"

#include "windows_fido_bridge/cbor/parse.hpp"
#include "windows_fido_bridge/cbor/types/value.hpp"

namespace wfb {

cbor_array::cbor_array(binary_reader& reader) {
    uint8_t type = reader.peek_uint8_t() >> 5;
    if (type != CBOR_ARRAY) {
        throw std::runtime_error("Invalid type value {:02x} for cbor_array"_format(type));
    }

    uint64_t num_elements = read_raw_length(reader);
    _array.reserve(num_elements);

    for (uint64_t i = 0; i < num_elements; i++) {
        _array.emplace_back(parse_cbor<cbor_value>(reader));
    }
}

bool cbor_array::operator==(const cbor_array& rhs) const { return _array == rhs._array; }
bool cbor_array::operator<(const cbor_array& rhs) const { return _array < rhs._array; }

void cbor_array::dump() const {
    std::stringstream ss;
    dump(ss);
    std::cerr << ss.str();
}

void cbor_array::dump(std::stringstream& ss) const {
    ss << '[';

    bool first = true;
    for (auto&& value : _array) {
        if (!first) {
            ss << ", ";
        }

        value.dump(ss);
        first = false;
    }

    ss << ']';
}

}  // namespace wfb
