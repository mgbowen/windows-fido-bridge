#pragma once

#include "binary_io.hpp"
#include "cbor.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <iostream>
#include <vector>

using json = nlohmann::json;

namespace wfb {

struct attested_credential_data {
    std::array<uint8_t, 16> authenticator_attestation_guid;
    std::vector<uint8_t> id;
    std::vector<uint8_t> public_key;

    attested_credential_data(binary_reader& reader) {
        reader.read_into(authenticator_attestation_guid);

        uint16_t credential_id_length = reader.read_be_uint16_t();
        id.resize(credential_id_length);
        reader.read_into(id);

        cbor_value public_key_obj = load_cbor(reader);
        public_key_obj.dump();
    }

    void dump() const {
        std::cerr << "Authenticator attestation GUID: ";

        unsigned int guid_i = 0;
        for (unsigned int group_size : {4, 2, 2, 2, 6}) {
            if (guid_i > 0) {
                std::cerr << '-';
            }

            for (unsigned int i = 0; i < group_size; i++) {
                std::cerr << "{:02x}"_format(authenticator_attestation_guid[guid_i + i]);
            }

            guid_i += group_size;
        }

        std::cerr << "\n";

        std::cerr << "Credential ID ({} bytes): "_format(id.size());

        for (uint8_t byte : id) {
            std::cerr << "{:02x}"_format(byte);
        }

        std::cerr << "\n";


    }
};

struct authenticator_data_extension {

};

struct authenticator_data {
    std::array<uint8_t, 32> relying_party_id_hash;

    uint8_t flags;
    bool user_present_result;
    bool user_verified_result;
    bool attested_credential_data_included;
    bool extension_data_included;

    uint32_t signature_count;
    std::optional<attested_credential_data> attested_credential;
    std::optional<std::vector<authenticator_data_extension>> extensions;

    authenticator_data(binary_reader& reader) {
        reader.read_into(relying_party_id_hash);

        flags = reader.read_uint8_t();
        user_present_result = flags & (1 << 0);
        user_verified_result = flags & (1 << 2);
        attested_credential_data_included = flags & (1 << 6);
        extension_data_included = flags & (1 << 7);

        signature_count = reader.read_be_uint32_t();

        if (attested_credential_data_included) {
            attested_credential = attested_credential_data{reader};
        }
    }

    void dump() const {
        std::cerr << "Relying party ID hash: ";

        for (uint8_t byte : relying_party_id_hash) {
            std::cerr << "{:02x}"_format(byte);
        }

        std::cerr << "\n";
        std::cerr << "Flags: 0x{:02x}\n"_format(flags);
        std::cerr << "    User present result: {}\n"_format(user_present_result);
        std::cerr << "    User verified result: {}\n"_format(user_verified_result);
        std::cerr << "    Attested credential data included: {}\n"_format(attested_credential_data_included);
        std::cerr << "    Extension data included: {}\n"_format(extension_data_included);
        std::cerr << "Signature count: {}\n"_format(signature_count);

        if (attested_credential) {
            attested_credential->dump();
        } else {
            std::cerr << "No attested credential data included\n";
        }
    }
};

}  // namespace wfb
