#include "cbor.hpp"

#include <nlohmann/json.hpp>

#include <iostream>
#include <optional>

namespace wfb {

cbor_value load_cbor(binary_reader& reader) {
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
            return cbor_text_string{reader}.string();
        }
        case CBOR_ARRAY: {
            return cbor_array{reader};
        }
        case CBOR_MAP: {
            return cbor_map{reader};
        }
    }

    throw std::runtime_error("Unrecognized CBOR type");
}

uint64_t read_raw_length(wfb::binary_reader& reader) {
    return wfb::cbor_integer{reader}.raw_value();
}

cbor_array::cbor_array(binary_reader& reader) {
    uint8_t type = reader.peek_uint8_t() >> 5;
    if (type != CBOR_ARRAY) {
        throw std::runtime_error("Invalid type value {:02x} for cbor_array"_format(type));
    }

    uint64_t num_elements = read_raw_length(reader);
    _array.reserve(num_elements);

    for (uint64_t i = 0; i < num_elements; i++) {
        _array.emplace_back(load_cbor(reader));
    }
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

cbor_map::cbor_map(binary_reader& reader) {
    uint8_t type = reader.peek_uint8_t() >> 5;
    if (type != CBOR_MAP) {
        throw std::runtime_error("Invalid type value {:02x} for cbor_map"_format(type));
    }

    uint64_t num_pairs = read_raw_length(reader);

    for (uint64_t i = 0; i < num_pairs; i++) {
        cbor_value key = load_cbor(reader);
        cbor_value value = load_cbor(reader);
        _map.emplace(std::make_pair(key, value));
    }
}

bool cbor_map::operator==(const cbor_map& rhs) const {
    return _map == rhs._map;
}

bool cbor_map::operator<(const cbor_map& rhs) const {
    return _map < rhs._map;
}

const cbor_value& cbor_map::operator[](std::string key) const { return _map.at(cbor_value{cbor_text_string{std::move(key)}}); }

void cbor_map::dump(std::stringstream& ss) const {
    ss << '{';

    bool first = true;
    for (auto&& pair : _map) {
        if (!first) {
            ss << ", ";
        }

        pair.first.dump(ss);
        ss << ": ";
        pair.second.dump(ss);

        first = false;
    }

    ss << '}';
}

}  // namespace wfb
