#pragma once

#include <windows_fido_bridge/cbor/detail.hpp>

#include <windows_fido_bridge/binary_io.hpp>

#include <cstdint>
#include <iostream>
#include <type_traits>
#include <sstream>

namespace wfb {

class cbor_value;

class cbor_array {
public:
    cbor_array() {}

    explicit cbor_array(binary_reader& reader);
    explicit cbor_array(const std::vector<cbor_value>& vec);
    cbor_array(std::initializer_list<cbor_value> list);

    const cbor_value& operator[](size_t index) const { return _array[index]; }

    void push_back(cbor_value val);

    size_t size() const { return _array.size(); }

    std::string dump_debug() const;
    void dump_debug(std::stringstream& ss) const;

    void dump_cbor_into(binary_writer& writer) const;

    std::vector<cbor_value> vector() const { return _array; }
    operator std::vector<cbor_value>() const { return vector(); }

    template <typename T>
    explicit operator std::vector<T>() const {
        return std::vector<T>{_array.begin(), _array.end()};
    }

    bool operator==(const cbor_array& rhs) const;
    bool operator<(const cbor_array& rhs) const;

private:
    std::vector<cbor_value> _array;
};

}  // namespace wfb
