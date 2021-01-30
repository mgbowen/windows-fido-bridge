#pragma once

#include <windows_fido_bridge/cbor/detail.hpp>
#include <windows_fido_bridge/cbor/parse_fwd.hpp>

#include <windows_fido_bridge/binary_io.hpp>

#include <cstdint>
#include <iostream>
#include <optional>
#include <map>
#include <type_traits>
#include <sstream>

namespace wfb {

template <typename TCborValue>
class basic_cbor_map {
public:
    basic_cbor_map() {}

    basic_cbor_map(std::initializer_list<std::pair<TCborValue, TCborValue>> list)
        : _map(list.begin(), list.end()) {}

    explicit basic_cbor_map(binary_reader& reader) {
        auto [type, num_pairs] = read_raw_length(reader);
        if (type != CBOR_MAP) {
            throw std::runtime_error("Invalid type value {:02x} for cbor_map"_format(type));
        }

        for (uint64_t i = 0; i < num_pairs; i++) {
            auto key = parse_cbor<TCborValue>(reader);
            auto value = parse_cbor<TCborValue>(reader);
            _map.emplace(std::move(key), std::move(value));
        }
    }

    void dump_cbor_into(binary_writer& writer) const {
        write_initial_byte_into(writer, CBOR_MAP, _map.size());

        for (auto&& pair : _map) {
            pair.first.dump_cbor_into(writer);
            pair.second.dump_cbor_into(writer);
        }
    }

    template <typename TKey, typename TValue>
    std::map<TKey, TValue> map() const {
        if constexpr (is_same_remove_cvref_v<TKey, TCborValue> &&
                      is_same_remove_cvref_v<TValue, TCborValue>) {
            return _map;
        }

        std::map<TKey, TValue> result;
        for (auto&& pair : _map) {
            result.emplace(static_cast<TKey>(pair.first), static_cast<TValue>(pair.second));
        }

        return result;
    }

    const std::map<TCborValue, TCborValue> map() const { return _map; }
    operator std::map<TCborValue, TCborValue>() const { return map(); }

    size_t size() const { return _map.size(); }

    template <typename TKey, typename TValue>
    explicit operator std::map<TKey, TValue>() const { return map<TKey, TValue>(); }

    template <typename TKey>
    TCborValue& operator[](TKey&& key) { return _map[key]; }

    template <typename TValue, typename TKey>
    TValue at(TKey&& key) { return static_cast<TValue>(_map.at(std::forward<TKey>(key))); }

    template <typename TValue, typename TKey>
    TValue at(TKey&& key) const { return static_cast<TValue>(_map.at(std::forward<TKey>(key))); }

    template <typename TValue>
    TValue at(TCborValue key) { return static_cast<TValue>(_map.at(key)); }

    template <typename TValue>
    TValue at(TCborValue key) const { return static_cast<TValue>(_map.at(key)); }

    TCborValue& at(TCborValue key) { return _map.at(key); }
    const TCborValue& at(TCborValue key) const { return _map.at(key); }

    std::vector<TCborValue> keys() const {
        std::vector<TCborValue> keys;
        for (const auto& item : _map) {
            keys.push_back(item.first);
        }

        return keys;
    }

    template <typename TValue = TCborValue, typename TKey = TCborValue>
    std::optional<TValue> try_at(TKey&& key) {
        auto it = _map.find(std::forward<TKey>(key));
        return it == _map.end()
            ? std::optional<TValue>{}
            : std::optional<TValue>{static_cast<TValue>(it->second)};
    }

    template <typename TValue = TCborValue, typename TKey = TCborValue>
    std::optional<TValue> try_at(TKey&& key) const {
        auto it = _map.find(std::forward<TKey>(key));
        return it == _map.cend()
            ? std::optional<TValue>{}
            : std::optional<TValue>{static_cast<TValue>(it->second)};
    }

    bool operator==(const basic_cbor_map<TCborValue>& rhs) const { return _map == rhs._map; }
    bool operator<(const basic_cbor_map<TCborValue>& rhs) const { return _map < rhs._map; }

    std::string dump_debug() const {
        std::stringstream ss;
        dump_debug(ss);
        return ss.str();
    }

    void dump_debug(std::stringstream& ss) const {
        ss << '{';

        bool first = true;
        for (auto&& pair : _map) {
            if (!first) {
                ss << ", ";
            }

            pair.first.dump_debug(ss);
            ss << ": ";
            pair.second.dump_debug(ss);

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
