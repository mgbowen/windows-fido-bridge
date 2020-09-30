#pragma once

#include <windows_fido_bridge/cbor/detail.hpp>
#include <windows_fido_bridge/exceptions.hpp>

#include <iostream>
#include <sstream>

namespace wfb {

CUSTOM_EXCEPTION(cbor_not_implemented_error, "Not implemented");

class cbor_null {
public:
    cbor_null();

    void dump_cbor_into(binary_writer& writer) const;

    void print_debug() const;
    void print_debug(std::stringstream& ss) const;

    bool operator==(const cbor_null& rhs) const;
    bool operator<(const cbor_null& rhs) const;
};

}  // namespace wfb
