#include "binary_io.hpp"
#include "bridge.hpp"
#include "cbor.hpp"
#include "util.hpp"
#include "webauthn.hpp"

#include <windows_fido_bridge/base64.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/exceptions.hpp>
#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

#include <nlohmann/json.hpp>

extern "C" {

#include "sk-api.h"

}

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string_view>

#include <sys/wait.h>
#include <unistd.h>

using json = nlohmann::json;

namespace wfb {

extern "C" {

/* Return the version of the middleware API */
uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

/* Enroll a U2F key (private key generation) */
int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
              const char *application, uint8_t flags, const char *pin,
              struct sk_option **options, struct sk_enroll_response **enroll_response) {
    json parameters = {
        {"type", "create"},
        {"challenge", base64_encode(reinterpret_cast<const unsigned char*>(challenge), challenge_len)},
        {"application", std::string{application}},
    };

    byte_array raw_output = invoke_windows_bridge(parameters.dump());
    json output = json::parse(raw_output);

    std::string cred_id = base64_decode(output["credential_id"].get<std::string>());

    std::string raw_attestation_object = base64_decode(output["attestation_object"].get<std::string>());
    json attestation_object = json::from_cbor(raw_attestation_object);
    const std::vector<uint8_t>& auth_data_bytes = *attestation_object["authData"].get_ptr<const json::binary_t*>();

    binary_reader reader{reinterpret_cast<const uint8_t*>(auth_data_bytes.data()), auth_data_bytes.size()};
    authenticator_data auth_data{reader};

    auto response = reinterpret_cast<sk_enroll_response*>(calloc(1, sizeof(**enroll_response)));

    response->public_key = reinterpret_cast<uint8_t*>(calloc(1, auth_data.attested_credential->public_key.size()));
    memcpy(response->public_key, auth_data.attested_credential->public_key.data(), auth_data.attested_credential->public_key.size());
    response->public_key_len = auth_data.attested_credential->public_key.size();

    response->key_handle = reinterpret_cast<uint8_t*>(calloc(1, auth_data.attested_credential->id.size()));
    memcpy(response->key_handle, auth_data.attested_credential->id.data(), auth_data.attested_credential->id.size());
    response->key_handle_len = auth_data.attested_credential->id.size();

    binary_reader reader2{reinterpret_cast<const uint8_t*>(raw_attestation_object.data()), raw_attestation_object.size()};
    auto cbor_attestation_object = load_cbor(reader2).get<cbor_map>();

    auto cbor_att_statement = cbor_attestation_object["attStmt"].get<cbor_map>();

    std::vector<uint8_t> cbor_signature = cbor_att_statement["sig"].get<cbor_byte_string>();

    response->signature = reinterpret_cast<uint8_t*>(calloc(1, cbor_signature.size()));
    memcpy(response->signature, cbor_signature.data(), cbor_signature.size());
    response->signature_len = cbor_signature.size();

    std::vector<cbor_value> cbor_x5c_array = cbor_att_statement["x5c"].get<cbor_array>();
    std::vector<uint8_t> cbor_x5c = cbor_x5c_array[0].get<cbor_byte_string>();

    response->attestation_cert = reinterpret_cast<uint8_t*>(calloc(1, cbor_x5c.size()));
    memcpy(response->attestation_cert, cbor_x5c.data(), cbor_x5c.size());
    response->attestation_cert_len = cbor_x5c.size();

    *enroll_response = response;
    return 0;
}

struct fido_signature {
    std::array<uint8_t, 32> sig_r;
    std::array<uint8_t, 32> sig_s;
};

fido_signature parse_fido_signature(const std::string& buffer) {
    // To avoid building or depending on a full ASN.1 parser, we hardcode the
    // format of the signature coming from the authenticator and bail out if we
    // see something we don't expect; we expect an ASN.1 SEQUENCE of two 256-bit
    // INTEGERs, see
    // https://www.w3.org/TR/webauthn/#signature-attestation-types.
    constexpr auto throw_invalid_signature = [] {
        throw std::runtime_error("Invalid or unrecognized signature received from authenticator");
    };

    // See explanation below about the expected size of the signature's INTEGERs
    if (buffer.size() < 70 || buffer.size() > 72) {
        throw_invalid_signature();
    }

    auto pos = reinterpret_cast<const uint8_t*>(buffer.data());

    // SEQUENCE
    if (*pos++ != 0x30) {
        throw_invalid_signature();
    }

    // SEQUENCE length between 68 and 70 bytes. It can differ because an ASN.1
    // INTEGER is left-padded with a single 0x00 byte if its MSB is set. This
    // means each INTEGER can be either 32 or 33 bytes, plus two bytes each for
    // their length for a range of [(32 + 2) * 2, (33 + 2) * 2], or [68, 70].
    size_t sequence_length = *pos++;
    if (sequence_length < 68 || sequence_length > 70) {
        throw_invalid_signature();
    }

    auto parse_integer = [&](std::array<uint8_t, 32>& dest_buffer) {
        // INTEGER
        if (*pos++ != 0x02) {
            throw_invalid_signature();
        }

        // INTEGER length
        size_t integer_length = *pos++;
        if (integer_length < 32 || integer_length > 33) {
            throw_invalid_signature();
        }

        if (integer_length == 33) {
            // Skip padding
            if (*pos != 0x00) {
                throw_invalid_signature();
            }

            pos++;
        }

        std::memcpy(dest_buffer.data(), pos, 32);
        pos += 32;
    };

    fido_signature result{};
    parse_integer(result.sig_r);
    parse_integer(result.sig_s);
    return result;
}

/* Sign a challenge */
int sk_sign(uint32_t alg, const uint8_t *message, size_t message_len,
            const char *application, const uint8_t *key_handle, size_t key_handle_len,
            uint8_t flags, const char *pin, struct sk_option **options,
            struct sk_sign_response **sign_response) {
    json parameters = {
        {"type", "sign"},
        {"message", base64_encode(reinterpret_cast<const unsigned char*>(message), message_len)},
        {"application", std::string{application}},
        {"key_handle", base64_encode(reinterpret_cast<const unsigned char*>(key_handle), key_handle_len)},
    };

    byte_array raw_output = invoke_windows_bridge(parameters.dump());
    json output = json::parse(raw_output);

    std::string authenticator_data_str = base64_decode(output["authenticator_data"].get<std::string>());
    binary_reader authenticator_data_reader{reinterpret_cast<const uint8_t*>(authenticator_data_str.data()), authenticator_data_str.size()};
    authenticator_data auth_data{authenticator_data_reader};

    auto response = reinterpret_cast<sk_sign_response*>(calloc(1, sizeof(**sign_response)));

    response->flags = auth_data.flags;
    response->counter = auth_data.signature_count;

    std::string signature_str = base64_decode(output["signature"].get<std::string>());
    fido_signature signature = parse_fido_signature(signature_str);

    response->sig_r = reinterpret_cast<uint8_t*>(calloc(1, signature.sig_r.size()));
    memcpy(response->sig_r, signature.sig_r.data(), signature.sig_r.size());
    response->sig_r_len = signature.sig_r.size();

    response->sig_s = reinterpret_cast<uint8_t*>(calloc(1, signature.sig_s.size()));
    memcpy(response->sig_s, signature.sig_s.data(), signature.sig_s.size());
    response->sig_s_len = signature.sig_s.size();

    *sign_response = response;
    return 0;
}

/* Enumerate all resident keys */
int sk_load_resident_keys(const char *pin, struct sk_option **options,
                          struct sk_resident_key ***rks, size_t *nrks) {
    return SSH_SK_ERR_UNSUPPORTED;
}

}  // extern "C"

}  // namespace wfb
