#pragma once

#include <windows_fido_bridge/cbor/detail.hpp>
#include <windows_fido_bridge/cbor/parse.hpp>

#include <windows_fido_bridge/binary_io.hpp>

#include <cstdint>
#include <iostream>
#include <map>
#include <type_traits>
#include <sstream>

namespace wfb {

template <typename TCborValue>
class basic_cbor_map {
public:
    explicit basic_cbor_map(binary_reader& reader) {
        uint8_t type = reader.peek_uint8_t() >> 5;
        if (type != CBOR_MAP) {
            throw std::runtime_error("Invalid type value {:02x} for cbor_map"_format(type));
        }

        uint64_t num_pairs = read_raw_length(reader);

        for (uint64_t i = 0; i < num_pairs; i++) {
            auto key = parse_cbor<TCborValue>(reader);
            auto value = parse_cbor<TCborValue>(reader);
            _map.emplace(key, value);
        }
    }

    operator std::map<TCborValue, TCborValue>() const { return _map; }

    bool operator==(const basic_cbor_map<TCborValue>& rhs) const { return _map == rhs._map; }
    bool operator<(const basic_cbor_map<TCborValue>& rhs) const { return _map < rhs._map; }

    template <typename TKey, typename TValue>
    explicit operator std::map<TKey, TValue>() const {
        std::map<TKey, TValue> result;
        for (auto&& pair : _map) {
            result.emplace(static_cast<TKey>(pair.first), static_cast<TValue>(pair.second));
        }

        return result;
    }

    const std::map<TCborValue, TCborValue>& map() const { return _map; }

    template <typename TKey>
    const TCborValue& operator[](TKey&& key) const {
        return _map.at(key);
    }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str() << "\n";
    }

    void dump(std::stringstream& ss) const {
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

private:
    std::map<TCborValue, TCborValue> _map;
};

class cbor_value;
using cbor_map = basic_cbor_map<cbor_value>;

}  // namespace wfb
