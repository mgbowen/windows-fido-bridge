#include "windows_fido_bridge/cbor/types/array.hpp"

#include "windows_fido_bridge/cbor/parse.hpp"
#include "windows_fido_bridge/cbor/types/value.hpp"

namespace wfb {

cbor_array::cbor_array(binary_reader& reader) {
    auto [type, num_elements] = read_raw_length(reader);
    if (type != CBOR_ARRAY) {
        throw std::runtime_error("Invalid type value {:02x} for cbor_array"_format(type));
    }

    _array.reserve(num_elements);

    for (uint64_t i = 0; i < num_elements; i++) {
        _array.emplace_back(parse_cbor<cbor_value>(reader));
    }
}

cbor_array::cbor_array(const std::vector<cbor_value>& vec)
    : _array(vec.cbegin(), vec.cend()) {}

cbor_array::cbor_array(std::initializer_list<cbor_value> list)
    : _array(list.begin(), list.end()) {}

void cbor_array::dump_cbor_into(binary_writer& writer) const {
    write_initial_byte_into(writer, CBOR_ARRAY, _array.size());

    for (auto&& value : _array) {
        value.dump_cbor_into(writer);
    }
}

bool cbor_array::operator==(const cbor_array& rhs) const { return _array == rhs._array; }
bool cbor_array::operator<(const cbor_array& rhs) const { return _array < rhs._array; }

std::string cbor_array::dump_debug() const {
    std::stringstream ss;
    dump_debug(ss);
    return ss.str();
}

void cbor_array::dump_debug(std::stringstream& ss) const {
    ss << '[';

    bool first = true;
    for (auto&& value : _array) {
        if (!first) {
            ss << ", ";
        }

        value.dump_debug(ss);
        first = false;
    }

    ss << ']';
}

}  // namespace wfb
