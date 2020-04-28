#include "webauthn.hpp"

namespace wfb {

attested_credential_data attested_credential_data::parse(std::string_view buffer) {
    return attested_credential_data::parse(buffer.data(), buffer.size());
}

attested_credential_data attested_credential_data::parse(const byte_vector& buffer) {
    return attested_credential_data::parse(buffer.data(), buffer.size());
}

attested_credential_data attested_credential_data::parse(const char* buffer, size_t length) {
    return attested_credential_data::parse(reinterpret_cast<const uint8_t*>(buffer), length);
}

attested_credential_data attested_credential_data::parse(const uint8_t* buffer, size_t length) {
    binary_reader reader(buffer, length);
    return attested_credential_data::parse(reader);
}

attested_credential_data attested_credential_data::parse(binary_reader& reader) {
    attested_credential_data result{};
    reader.read_into(result.authenticator_attestation_guid);

    uint16_t credential_id_length = reader.read_be_uint16_t();
    result.id.resize(credential_id_length);
    reader.read_into(result.id);

    auto public_key_map = parse_cbor<cbor_map>(reader);
    auto x_coordinate_bytes = public_key_map[-2].get<byte_vector>();
    auto y_coordinate_bytes = public_key_map[-3].get<byte_vector>();

    result.public_key.resize(1 + x_coordinate_bytes.size() + y_coordinate_bytes.size());
    result.public_key[0] = 0x04;
    std::memcpy(result.public_key.data() + 1, x_coordinate_bytes.data(), x_coordinate_bytes.size());
    std::memcpy(result.public_key.data() + 1 + x_coordinate_bytes.size(), y_coordinate_bytes.data(), y_coordinate_bytes.size());

    return result;
}

void attested_credential_data::dump() const {
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
    std::cerr << "Public key ({} bytes): "_format(public_key.size());
    for (uint8_t byte : public_key) {
        std::cerr << "{:02x}"_format(byte);
    }

    std::cerr << "\n";
}

authenticator_data authenticator_data::parse(std::string_view buffer) {
    return authenticator_data::parse(buffer.data(), buffer.size());
}

authenticator_data authenticator_data::parse(const byte_vector& buffer) {
    return authenticator_data::parse(buffer.data(), buffer.size());
}

authenticator_data authenticator_data::parse(const char* buffer, size_t length) {
    return authenticator_data::parse(reinterpret_cast<const uint8_t*>(buffer), length);
}

authenticator_data authenticator_data::parse(const uint8_t* buffer, size_t length) {
    binary_reader reader(buffer, length);
    return authenticator_data::parse(reader);
}

authenticator_data authenticator_data::parse(binary_reader& reader) {
    authenticator_data result{};
    reader.read_into(result.relying_party_id_hash);

    result.flags = reader.read_uint8_t();
    result.signature_count = reader.read_be_uint32_t();

    if (result.attested_credential_data_included()) {
        result.attested_credential = attested_credential_data::parse(reader);
    }

    return result;
}

void authenticator_data::dump() const {
    std::cerr << "Relying party ID hash: ";

    for (uint8_t byte : relying_party_id_hash) {
        std::cerr << "{:02x}"_format(byte);
    }

    std::cerr << "\n";
    std::cerr << "Flags: 0x{:02x}\n"_format(flags);
    std::cerr << "    User present result: {}\n"_format(user_present_result());
    std::cerr << "    User verified result: {}\n"_format(user_verified_result());
    std::cerr << "    Attested credential data included: {}\n"_format(attested_credential_data_included());
    std::cerr << "    Extension data included: {}\n"_format(extension_data_included());
    std::cerr << "Signature count: {}\n"_format(signature_count);

    if (attested_credential) {
        attested_credential->dump();
    } else {
        std::cerr << "No attested credential data included\n";
    }
}

}  // namespace wfb
