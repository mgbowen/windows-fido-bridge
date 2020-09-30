#include "webauthn.hpp"

namespace wfb {

attested_credential_data attested_credential_data::parse(binary_reader& reader) {
    attested_credential_data result{};
    reader.read_into(result.authenticator_attestation_guid);

    uint16_t credential_id_length = reader.read_be_uint16_t();
    result.id.resize(credential_id_length);
    reader.read_into(result.id);

    auto public_key_map = parse_cbor<cbor_map>(reader);
    auto x_coordinate_bytes = public_key_map.at(-2).get<byte_vector>();
    auto y_coordinate_bytes = public_key_map.at(-3).get<byte_vector>();

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

fido_signature fido_signature::parse(binary_reader& reader) {
    // To avoid building or depending on a full ASN.1 parser, we hardcode the
    // format of the signature coming from the authenticator and bail out if we
    // see something we don't expect; we expect an ASN.1 SEQUENCE of two 256-bit
    // INTEGERs, see
    // https://www.w3.org/TR/webauthn/#signature-attestation-types.
    constexpr auto throw_invalid_signature = [] {
        throw std::runtime_error("Invalid or unrecognized signature received from authenticator");
    };

    // SEQUENCE
    if (reader.read_uint8_t() != 0x30) {
        throw_invalid_signature();
    }

    // SEQUENCE length between 68 and 70 bytes. It can differ because an ASN.1
    // INTEGER is left-padded with a single 0x00 byte if its MSB is set. This
    // means each INTEGER can be either 32 or 33 bytes, plus two bytes each for
    // their length for a range of [(32 + 2) * 2, (33 + 2) * 2], or [68, 70].
    uint8_t sequence_length = reader.read_uint8_t();
    if (sequence_length < 68 || sequence_length > 70) {
        throw_invalid_signature();
    }

    auto parse_integer = [&reader, &throw_invalid_signature](std::array<uint8_t, 32>& dest_buffer) {
        // INTEGER
        if (reader.read_uint8_t() != 0x02) {
            throw_invalid_signature();
        }

        // INTEGER length
        uint8_t integer_length = reader.read_uint8_t();
        if (integer_length < 32 || integer_length > 33) {
            throw_invalid_signature();
        }

        if (integer_length == 33) {
            // Skip padding
            if (reader.read_uint8_t() != 0x00) {
                throw_invalid_signature();
            }
        }

        reader.read_into(dest_buffer);
    };

    fido_signature result{};
    parse_integer(result.sig_r);
    parse_integer(result.sig_s);
    return result;
}

}  // namespace wfb
