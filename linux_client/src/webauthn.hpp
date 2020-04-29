#pragma once

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/util.hpp>

#include <array>
#include <iostream>
#include <string_view>
#include <vector>

namespace wfb {

struct attested_credential_data {
    byte_array<16> authenticator_attestation_guid;
    byte_vector id;
    byte_vector public_key;

    static attested_credential_data parse(binary_reader& reader);
    static attested_credential_data parse(binary_reader&& reader) {
        return attested_credential_data::parse(reader);
    }

    void dump() const;
};

struct authenticator_data_extension {

};

struct authenticator_data {
    std::array<uint8_t, 32> relying_party_id_hash;

    uint8_t flags;
    bool user_present_result() const { return flags & (1 << 0); }
    bool user_verified_result() const { return flags & (1 << 2); }
    bool attested_credential_data_included() const { return flags & (1 << 6); }
    bool extension_data_included() const { return flags & (1 << 7); }

    uint32_t signature_count;
    std::optional<attested_credential_data> attested_credential;
    std::optional<std::vector<authenticator_data_extension>> extensions;

    static authenticator_data parse(binary_reader& reader);
    static authenticator_data parse(binary_reader&& reader) {
        return authenticator_data::parse(reader);
    }

    void dump() const;
};

}  // namespace wfb
