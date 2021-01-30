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
    explicit cbor_array(binary_reader& reader);
    explicit cbor_array(const std::vector<cbor_value>& vec);
    cbor_array(std::initializer_list<cbor_value> list);

    void dump_cbor_into(binary_writer& writer) const;

    operator std::vector<cbor_value>() const { return _array; }

    const cbor_value& operator[](size_t index) const { return _array[index]; }

    bool operator==(const cbor_array& rhs) const;
    bool operator<(const cbor_array& rhs) const;

    template <typename T>
    explicit operator std::vector<T>() const {
        return std::vector<T>{_array.begin(), _array.end()};
    }

    size_t size() const { return _array.size(); }

    std::string dump_debug() const;
    void dump_debug(std::stringstream& ss) const;

private:
    std::vector<cbor_value> _array;
};

}  // namespace wfb
