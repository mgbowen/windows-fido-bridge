#pragma once

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/types.hpp>

#include <windows.h>
#include <webauthn.h>
#include "undocumented_microsoft_webauthn.hpp"

#include <spdlog/spdlog.h>

#include <memory>
#include <optional>
#include <span>
#include <string>

// Win32 forward declarations.
struct _WEBAUTHN_ASSERTION;
typedef _WEBAUTHN_ASSERTION WEBAUTHN_ASSERTION;
struct _WEBAUTHN_CREDENTIAL_ATTESTATION;
typedef _WEBAUTHN_CREDENTIAL_ATTESTATION WEBAUTHN_CREDENTIAL_ATTESTATION;

namespace wfb {

struct unique_webauthn_credential_attestation_ptr_deleter {
    void operator()(WEBAUTHN_CREDENTIAL_ATTESTATION* ptr) const noexcept;
};

using unique_webauthn_credential_attestation_ptr =
    std::unique_ptr<WEBAUTHN_CREDENTIAL_ATTESTATION, unique_webauthn_credential_attestation_ptr_deleter>;

inline auto make_unique_webauthn_credential_attestation_ptr(WEBAUTHN_CREDENTIAL_ATTESTATION* ptr) {
    return unique_webauthn_credential_attestation_ptr(ptr);
}

struct unique_webauthn_assertion_ptr_deleter {
    void operator()(WEBAUTHN_ASSERTION* ptr) const noexcept;
};

using unique_webauthn_assertion_ptr =
    std::unique_ptr<WEBAUTHN_ASSERTION, unique_webauthn_assertion_ptr_deleter>;

inline auto make_unique_webauthn_assertion_ptr(WEBAUTHN_ASSERTION* ptr) {
    return unique_webauthn_assertion_ptr(ptr);
}

unique_webauthn_credential_attestation_ptr create_windows_webauthn_credential(
    HWND parent_window_handle,
    int ssh_algorithm,
    std::string_view ssh_application,
    std::string_view ssh_user,
    std::span<const uint8_t> ssh_challenge_bytes,
    bool ssh_user_verification_required
);

unique_webauthn_assertion_ptr create_windows_webauthn_assertion(
    HWND parent_window_handle,
    std::string_view ssh_application,
    std::span<const uint8_t> ssh_message_bytes,
    std::span<const uint8_t> ssh_key_handle_bytes,
    bool ssh_user_verification_required
);

struct attested_credential_data {
    byte_array<16> authenticator_attestation_guid;
    byte_vector id;
    byte_vector public_key;

    static attested_credential_data parse(binary_reader& reader);
    static attested_credential_data parse(binary_reader&& reader) {
        return attested_credential_data::parse(reader);
    }

    std::string dump_debug() const;
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

    static authenticator_data parse(binary_reader& reader);
    static authenticator_data parse(binary_reader&& reader) {
        return authenticator_data::parse(reader);
    }

    std::string dump_debug() const;
};

struct fido_signature {
    std::optional<byte_vector> sig_r;
    std::optional<byte_vector> sig_s;

    static fido_signature parse_ed25519_sk_signature(binary_reader& reader);
    static fido_signature parse_ed25519_sk_signature(binary_reader&& reader) {
        return fido_signature::parse_ed25519_sk_signature(reader);
    }

    static fido_signature parse_ecdsa_sk_signature(binary_reader& reader);
    static fido_signature parse_ecdsa_sk_signature(binary_reader&& reader) {
        return fido_signature::parse_ecdsa_sk_signature(reader);
    }
};

std::string extract_attestation_object_format(const cbor_map& attestation_object);

}  // namespace wfb
