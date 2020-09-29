#include "bridge.hpp"
#include "webauthn.hpp"

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/exceptions.hpp>
#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

extern "C" {

#include "sk-api.h"

}

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#include <sys/wait.h>
#include <unistd.h>

namespace wfb {

namespace {

std::tuple<uint8_t*, size_t> calloc_from_data(const uint8_t* buffer, size_t size);
std::tuple<uint8_t*, size_t> calloc_from_data(const char* buffer, size_t size);
std::tuple<uint8_t*, size_t> calloc_from_data(const byte_vector& buffer);
std::tuple<uint8_t*, size_t> calloc_from_data(const std::string& buffer);

template <size_t N>
std::tuple<uint8_t*, size_t> calloc_from_data(const byte_array<N>& buffer) {
    return calloc_from_data(buffer.data(), buffer.size());
}

bool is_user_verification_required_flag_set(uint8_t flags) {
    return (flags & SSH_SK_USER_VERIFICATION_REQD) == SSH_SK_USER_VERIFICATION_REQD;
}

bool is_user_verification_required(uint8_t flags) {
    const char* force_env_var = std::getenv("WINDOWS_FIDO_BRIDGE_FORCE_USER_VERIFICATION");
    return (force_env_var != nullptr) || is_user_verification_required_flag_set(flags);
}

}  // namespace

extern "C" {

/* Return the version of the middleware API */
uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

/* Enroll a U2F key (private key generation) */
int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
              const char *application, uint8_t flags, const char *pin,
              struct sk_option **options, struct sk_enroll_response **enroll_response) {
    if (alg != SSH_SK_ECDSA) {
        // TODO
        return SSH_SK_ERR_UNSUPPORTED;
    }

    wfb::cbor_map parameters = {
        {"type", "create"},
        {"challenge", byte_string{challenge, challenge + challenge_len}},
        {"application", application},

        // Explicitly only check the flag provided by OpenSSH (and not the force
        // environment variable) so the user doesn't accidentally create keys
        // that require user verification without them specifying it explicitly
        // on ssh-keygen's command line.
        {"user_verification_required", is_user_verification_required_flag_set(flags)},
    };

    byte_vector raw_output = invoke_windows_bridge(wfb::dump_cbor(parameters));
    auto output = parse_cbor<cbor_map>(raw_output);

    auto raw_attestation_object = output.at<byte_string>("attestation_object");
    auto attestation_object = parse_cbor<cbor_map>(raw_attestation_object);
    auto auth_data = authenticator_data::parse({attestation_object.at<byte_vector>("authData")});
    auto attestation_statement = attestation_object.at<cbor_map>("attStmt");
    byte_vector signature = attestation_statement.at<cbor_byte_string>("sig");
    byte_vector x5c = attestation_statement.at<cbor_array>("x5c")[0].get<cbor_byte_string>();

    // Construct the response to send back to OpenSSH. The ownership of the
    // memory we allocate here is transferred to OpenSSH; they are responsible
    // for deallocating it.
    auto response = reinterpret_cast<sk_enroll_response*>(calloc(1, sizeof(**enroll_response)));

    std::tie(response->public_key, response->public_key_len) =
        calloc_from_data(auth_data.attested_credential->public_key);

    std::tie(response->key_handle, response->key_handle_len) =
        calloc_from_data(auth_data.attested_credential->id);

    std::tie(response->signature, response->signature_len) = calloc_from_data(signature);
    std::tie(response->attestation_cert, response->attestation_cert_len) = calloc_from_data(x5c);

#if WFB_SK_API_VERSION == 7
    // TODO: provide the raw CBOR-encoded attestation data from the security key
    response->authdata = nullptr;
    response->authdata_len = 0;
#endif

    *enroll_response = response;
    return 0;
}

struct fido_signature {
    std::array<uint8_t, 32> sig_r;
    std::array<uint8_t, 32> sig_s;
};

fido_signature parse_fido_signature(const byte_string& buffer) {
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
int sk_sign(uint32_t alg, const uint8_t *data, size_t datalen,
            const char *application, const uint8_t *key_handle, size_t key_handle_len,
            uint8_t flags, const char *pin, struct sk_option **options,
            struct sk_sign_response **sign_response) {
    if (alg != SSH_SK_ECDSA) {
        // TODO
        return SSH_SK_ERR_UNSUPPORTED;
    }

    wfb::cbor_map parameters = {
        {"type", "sign"},
        {"message", byte_string{data, data + datalen}},
        {"application", application},
        {"key_handle", byte_string{key_handle, key_handle + key_handle_len}},
        {"user_verification_required", is_user_verification_required(flags)},
    };

    byte_vector raw_output = invoke_windows_bridge(wfb::dump_cbor(parameters));
    auto output = wfb::parse_cbor<cbor_map>(raw_output);

    byte_string raw_auth_data = output.at<byte_string>("authenticator_data");
    auto auth_data = authenticator_data::parse({raw_auth_data});

    auto response = reinterpret_cast<sk_sign_response*>(calloc(1, sizeof(**sign_response)));

    response->flags = auth_data.flags;
    response->counter = auth_data.signature_count;

    auto raw_signature = output.at<byte_string>("signature");
    fido_signature signature = parse_fido_signature(raw_signature);

    std::tie(response->sig_r, response->sig_r_len) = calloc_from_data(signature.sig_r);
    std::tie(response->sig_s, response->sig_s_len) = calloc_from_data(signature.sig_s);

    *sign_response = response;
    return 0;
}

/* Enumerate all resident keys */
int sk_load_resident_keys(const char *pin, struct sk_option **options,
                          struct sk_resident_key ***rks, size_t *nrks) {
    return SSH_SK_ERR_UNSUPPORTED;
}

}  // extern "C"

namespace {

std::tuple<uint8_t*, size_t> calloc_from_data(const uint8_t* buffer, size_t size) {
    uint8_t* result = reinterpret_cast<uint8_t*>(calloc(1, size));
    memcpy(result, buffer, size);
    return {result, size};
}

std::tuple<uint8_t*, size_t> calloc_from_data(const char* buffer, size_t size) {
    return calloc_from_data(reinterpret_cast<const uint8_t*>(buffer), size);
}

std::tuple<uint8_t*, size_t> calloc_from_data(const byte_vector& buffer) {
    return calloc_from_data(buffer.data(), buffer.size());
}

std::tuple<uint8_t*, size_t> calloc_from_data(const std::string& buffer) {
    return calloc_from_data(buffer.data(), buffer.size());
}

}  // namespace

}  // namespace wfb
