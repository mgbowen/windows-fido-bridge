#include "webauthn.hpp"

#include <windows_fido_bridge/windows_error.hpp>
#include <windows_fido_bridge/windows_fwd.hpp>
#include <windows_fido_bridge/windows_util.hpp>

#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/types.hpp>

#include <iostream>

namespace wfb {

namespace {

struct webauthn_methods {
    decltype(&WebAuthNGetApiVersionNumber) GetApiVersionNumber;
    decltype(&WebAuthNAuthenticatorMakeCredential) AuthenticatorMakeCredential;
    decltype(&WebAuthNAuthenticatorGetAssertion) AuthenticatorGetAssertion;
    decltype(&WebAuthNGetErrorName) GetErrorName;
    decltype(&WebAuthNFreeAssertion) FreeAssertion;
    decltype(&WebAuthNFreeCredentialAttestation) FreeCredentialAttestation;
    std::shared_ptr<void> library_handle;

    static webauthn_methods load() {
        auto library_name = "webauthn.dll";
        HINSTANCE library = LoadLibraryA(library_name);
        if (library == nullptr) {
            throw_windows_exception("Failed to load {}"_format(library_name));
        }

        std::shared_ptr<void> library_handle(library, [](HINSTANCE ptr) { FreeLibrary(ptr); });

        return webauthn_methods{
            .GetApiVersionNumber =
                get_proc_address<decltype(&WebAuthNGetApiVersionNumber)>(
                    library, "WebAuthNGetApiVersionNumber"
                ),
            .AuthenticatorMakeCredential =
                get_proc_address<decltype(&WebAuthNAuthenticatorMakeCredential)>(
                    library, "WebAuthNAuthenticatorMakeCredential"
                ),
            .AuthenticatorGetAssertion =
                get_proc_address<decltype(&WebAuthNAuthenticatorGetAssertion)>(
                    library, "WebAuthNAuthenticatorGetAssertion"
                ),
            .GetErrorName =
                get_proc_address<decltype(&WebAuthNGetErrorName)>(library, "WebAuthNGetErrorName"),
            .FreeAssertion =
                get_proc_address<decltype(&WebAuthNFreeAssertion)>(library, "WebAuthNFreeAssertion"),
            .FreeCredentialAttestation =
                get_proc_address<decltype(&WebAuthNFreeCredentialAttestation)>(
                    library, "WebAuthNFreeCredentialAttestation"
                ),
            .library_handle = std::move(library_handle),
        };
    }
};

webauthn_methods webauthn = webauthn_methods::load();

// https://tools.ietf.org/html/rfc8152#section-7.1
constexpr const int64_t COSE_KEY_PARAMETER_KTY = 1;
constexpr const int64_t COSE_KEY_PARAMETER_ALG = 3;

// https://tools.ietf.org/html/rfc8152#section-13.1.1
constexpr const int64_t COSE_KEY_PARAMETER_EC2_CRV = -1;
constexpr const int64_t COSE_KEY_PARAMETER_EC2_X_COORD = -2;
constexpr const int64_t COSE_KEY_PARAMETER_EC2_Y_COORD = -3;

// https://tools.ietf.org/html/rfc8152#section-13
enum class cose_key_type {
    RESERVED = 0,
    OKP = 1,
    EC2 = 2,
    SYMMETRIC = 4,
};

std::string get_cose_key_type_description(cose_key_type kty);
std::string get_cose_key_type_debug_description(cose_key_type kty);

// Names based on Microsoft's WebAuthn API:
// https://github.com/microsoft/webauthn
enum class cose_key_algorithm {
    ECDSA_P256_WITH_SHA256 = -7,
    ECDSA_P384_WITH_SHA384 = -35,
    ECDSA_P521_WITH_SHA512 = -36,
    RSA_PSS_WITH_SHA256 = -37,
    RSA_PSS_WITH_SHA384 = -38,
    RSA_RSS_WITH_SHA512 = -39,
    RSASSA_PKCS1_V1_5_WITH_SHA256 = -257,
    RSASSA_PKCS1_V1_5_WITH_SHA384 = -258,
    RSASSA_PKCS1_V1_5_WITH_SHA512 = -259,
};

std::string get_cose_key_algorithm_description(cose_key_algorithm alg);
std::string get_cose_key_algorithm_debug_description(cose_key_algorithm alg);

// https://tools.ietf.org/html/rfc8152#section-13.1
enum class cose_ec2_curve_type {
    P256 = 1,
    P384 = 2,
    P521 = 3,
};

std::string get_cose_ec2_curve_type_description(cose_ec2_curve_type crv);
std::string get_cose_ec2_curve_type_debug_description(cose_ec2_curve_type crv);

byte_vector parse_attested_credential_public_key(binary_reader& reader);

}  // namespace

void unique_webauthn_assertion_ptr_deleter::operator()(WEBAUTHN_ASSERTION* ptr) const noexcept {
    webauthn.FreeAssertion(ptr);
}

void unique_webauthn_credential_attestation_ptr_deleter::operator()(
    WEBAUTHN_CREDENTIAL_ATTESTATION* ptr
) const noexcept {
    webauthn.FreeCredentialAttestation(ptr);
}

unique_webauthn_credential_attestation_ptr create_windows_webauthn_credential(
    HWND parent_window_handle,
    std::string_view ssh_application,
    std::string_view ssh_user,
    std::span<const uint8_t> ssh_challenge_bytes,
    bool ssh_user_verification_required
) {
    std::wstring relying_party_id = string_to_wide_string(ssh_application);
    std::wstring wide_ssh_user = string_to_wide_string(ssh_user);

    WEBAUTHN_RP_ENTITY_INFORMATION entity_info = {
        .dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        .pwszId = relying_party_id.c_str(),
        .pwszName = L"OpenSSH via windows-fido-bridge",
    };

    
    // OpenSSH doesn't give us this, so just use a placeholder
    std::string user_id = "(null)";

    WEBAUTHN_USER_ENTITY_INFORMATION user_info = {
        .dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        .cbId = static_cast<DWORD>(user_id.size()),
        .pbId = reinterpret_cast<BYTE*>(user_id.data()),
        .pwszName = wide_ssh_user.c_str(),
        .pwszIcon = nullptr,
        .pwszDisplayName = wide_ssh_user.c_str(),
    };

    std::array<WEBAUTHN_COSE_CREDENTIAL_PARAMETER, 1> cose_credential_parameters_array{
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER{
            .dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            .lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        },
    };

    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS cose_credential_parameters{
        static_cast<DWORD>(cose_credential_parameters_array.size()),
        cose_credential_parameters_array.data()
    };

    // The Windows WebAuthn API requires a mutable copy of the challenge bytes,
    // so create our own copy of them.
    byte_string mutable_ssh_challenge_bytes{cbegin(ssh_challenge_bytes), cend(ssh_challenge_bytes)};

    WEBAUTHN_CLIENT_DATA client_data = {
        .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        .cbClientDataJSON = static_cast<DWORD>(mutable_ssh_challenge_bytes.size()),
        .pbClientDataJSON = reinterpret_cast<BYTE*>(mutable_ssh_challenge_bytes.data()),
        .pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = {
        .dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
        .dwUserVerificationRequirement = static_cast<DWORD>(
            ssh_user_verification_required
                ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        ),
    };

    WEBAUTHN_CREDENTIAL_ATTESTATION* raw_credential_attestation = nullptr;

    auto result = webauthn.AuthenticatorMakeCredential(
        parent_window_handle,
        &entity_info,
        &user_info,
        &cose_credential_parameters,
        &client_data,
        &options,
        &raw_credential_attestation
    );

    auto credential_attestation = make_unique_webauthn_credential_attestation_ptr(
        raw_credential_attestation
    );

    if (result != S_OK) {
        std::string error_str = wide_string_to_string(webauthn.GetErrorName(result));
        throw_windows_exception(result, "Failed to make WebAuthN credential ({})"_format(error_str));
    }

    return credential_attestation;
}

unique_webauthn_assertion_ptr create_windows_webauthn_assertion(
    HWND parent_window_handle,
    std::string_view ssh_application,
    std::span<const uint8_t> ssh_message_bytes,
    std::span<const uint8_t> ssh_key_handle_bytes,
    bool ssh_user_verification_required
) {
    // The Windows WebAuthn API requires mutable copies of the message and key
    // handle bytes, so create our own copies of them.
    byte_string mutable_ssh_message_bytes{cbegin(ssh_message_bytes), cend(ssh_message_bytes)};
    auto client_data = WEBAUTHN_CLIENT_DATA{
        .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        .cbClientDataJSON = static_cast<DWORD>(mutable_ssh_message_bytes.size()),
        .pbClientDataJSON = reinterpret_cast<PBYTE>(mutable_ssh_message_bytes.data()),
        .pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    byte_string mutable_ssh_key_handle_bytes{cbegin(ssh_key_handle_bytes), cend(ssh_key_handle_bytes)};
    std::array<WEBAUTHN_CREDENTIAL, 1> credentials_arr = {
        WEBAUTHN_CREDENTIAL{
            .dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            .cbId = static_cast<DWORD>(mutable_ssh_key_handle_bytes.size()),
            .pbId = reinterpret_cast<PBYTE>(mutable_ssh_key_handle_bytes.data()),
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        },
    };

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {
        .dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
        .CredentialList = WEBAUTHN_CREDENTIALS{
            .cCredentials = static_cast<DWORD>(credentials_arr.size()),
            .pCredentials = credentials_arr.data(),
        },
        .dwUserVerificationRequirement = static_cast<DWORD>(
            ssh_user_verification_required
                ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        ),
    };

    std::wstring relying_party_id = string_to_wide_string(ssh_application);

    WEBAUTHN_ASSERTION* raw_assertion = nullptr;

    auto result = webauthn.AuthenticatorGetAssertion(
        parent_window_handle,
        relying_party_id.c_str(),
        &client_data,
        &options,
        &raw_assertion
    );

    auto assertion = make_unique_webauthn_assertion_ptr(raw_assertion);

    if (result != S_OK) {
        std::string error_str = wide_string_to_string(webauthn.GetErrorName(result));
        throw_windows_exception(result, "Failed to get WebAuthN assertion ({})"_format(error_str));
    }

    return assertion;
}

attested_credential_data attested_credential_data::parse(binary_reader& reader) {
    spdlog::debug("Parsing attested credential data");

    attested_credential_data result{};
    reader.read_into(result.authenticator_attestation_guid);

    uint16_t credential_id_length = reader.read_be_uint16_t();
    result.id.resize(credential_id_length);
    reader.read_into(result.id);

    result.public_key = parse_attested_credential_public_key(reader);

    spdlog::debug("Attested credential data parsed successfully");
    return result;
}

std::string attested_credential_data::dump_debug() const {
    std::stringstream ss;

    ss << "Authenticator attestation GUID: ";

    unsigned int guid_i = 0;
    for (unsigned int group_size : {4, 2, 2, 2, 6}) {
        if (guid_i > 0) {
            ss << '-';
        }

        for (unsigned int i = 0; i < group_size; i++) {
            ss << "{:02x}"_format(authenticator_attestation_guid[guid_i + i]);
        }

        guid_i += group_size;
    }

    ss << "\n";
    ss << "Credential ID ({} bytes): 0x"_format(id.size());
    for (uint8_t byte : id) {
        ss << "{:02x}"_format(byte);
    }

    ss << "\n";
    ss << "Public key ({} bytes): 0x"_format(public_key.size());
    for (uint8_t byte : public_key) {
        ss << "{:02x}"_format(byte);
    }

    return ss.str();
}

authenticator_data authenticator_data::parse(binary_reader& reader) {
    spdlog::debug("Parsing authenticator data");

    authenticator_data result{};
    reader.read_into(result.relying_party_id_hash);

    result.flags = reader.read_uint8_t();
    result.signature_count = reader.read_be_uint32_t();

    if (result.attested_credential_data_included()) {
        result.attested_credential = attested_credential_data::parse(reader);
    }

    spdlog::debug("Authenticator data parsed successfully");
    return result;
}

std::string authenticator_data::dump_debug() const {
    std::stringstream ss;
    ss << "Relying party ID hash: 0x";

    for (uint8_t byte : relying_party_id_hash) {
        ss << "{:02x}"_format(byte);
    }

    ss << "\n";
    ss << "Flags: 0b{:08b}\n"_format(flags);
    ss << "    User present result: {}\n"_format(user_present_result());
    ss << "    User verified result: {}\n"_format(user_verified_result());
    ss << "    Attested credential data included: {}\n"_format(attested_credential_data_included());
    ss << "    Extension data included: {}\n"_format(extension_data_included());
    ss << "Signature count: {}\n"_format(signature_count);

    if (attested_credential) {
        ss << attested_credential->dump_debug() << "\n";
    } else {
        ss << "No attested credential data included\n";
    }

    return ss.str();
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

std::string extract_attestation_object_format(const cbor_map& attestation_object) {
    auto raw_attestation_object_format = attestation_object.try_at("fmt");
    spdlog::debug(
        "Attestation object format: {}",
        raw_attestation_object_format ? raw_attestation_object_format->dump_debug() : "(missing)"
    );
    if (!raw_attestation_object_format) {
        throw std::runtime_error("Missing attestation object format");
    }

    auto format = static_cast<std::string>(raw_attestation_object_format->get<cbor_text_string>());
    if (format != "packed" && format != "fido-u2f") {
        throw std::runtime_error("Invalid or unknown attestation object format");
    }

    return format;
}

namespace {

std::string get_cose_key_type_description(cose_key_type kty) {
    switch (kty) {
        case cose_key_type::RESERVED: return "Reserved";
        case cose_key_type::OKP: return "Octet Key Pair";
        case cose_key_type::EC2: return "Elliptic Curve Keys w/ x- and y-coordinate pair";
        case cose_key_type::SYMMETRIC: return "Symmetric Keys";
        default: return "(Unknown)";
    }
}

std::string get_cose_key_type_debug_description(cose_key_type kty) {
    return "{} (kty = {})"_format(get_cose_key_type_description(kty), kty);
}

std::string get_cose_key_algorithm_description(cose_key_algorithm alg) {
    // https://www.iana.org/assignments/cose/cose.xhtml
    switch (alg) {
        case cose_key_algorithm::ECDSA_P256_WITH_SHA256: return "ECDSA w/ SHA-256";
        case cose_key_algorithm::ECDSA_P384_WITH_SHA384: return "ECDSA w/ SHA-384";
        case cose_key_algorithm::ECDSA_P521_WITH_SHA512: return "ECDSA w/ SHA-512";
        case cose_key_algorithm::RSA_PSS_WITH_SHA256: return "RSASSA-PSS w/ SHA-256";
        case cose_key_algorithm::RSA_PSS_WITH_SHA384: return "RSASSA-PSS w/ SHA-384";
        case cose_key_algorithm::RSA_RSS_WITH_SHA512: return "RSASSA-PSS w/ SHA-512";
        case cose_key_algorithm::RSASSA_PKCS1_V1_5_WITH_SHA256: return "RSASSA-PKCS1-v1_5 using SHA-256";
        case cose_key_algorithm::RSASSA_PKCS1_V1_5_WITH_SHA384: return "RSASSA-PKCS1-v1_5 using SHA-384";
        case cose_key_algorithm::RSASSA_PKCS1_V1_5_WITH_SHA512: return "RSASSA-PKCS1-v1_5 using SHA-512";
        default: return "(Unknown)";
    }
}

std::string get_cose_key_algorithm_debug_description(cose_key_algorithm alg) {
    return "{} (alg = {})"_format(get_cose_key_algorithm_description(alg), alg);
}

std::string get_cose_ec2_curve_type_description(cose_ec2_curve_type crv) {
    switch (crv) {
        case cose_ec2_curve_type::P256: return "P-256";
        case cose_ec2_curve_type::P384: return "P-384";
        case cose_ec2_curve_type::P521: return "P-521";
        default: return "(Unknown)";
    }
}

std::string get_cose_ec2_curve_type_debug_description(cose_ec2_curve_type crv) {
    return "{} (crv = {})"_format(get_cose_ec2_curve_type_description(crv), crv);
}

byte_vector parse_attested_credential_public_key(binary_reader& reader) {
    spdlog::debug("Parsing public key CBOR map in attested credential data");
    auto public_key_map = parse_cbor<cbor_map>(reader);
    spdlog::debug("Public key CBOR map keys: {}", cbor_array{public_key_map.keys()}.dump_debug());

    auto raw_kty = public_key_map.try_at<cbor_integer>(COSE_KEY_PARAMETER_KTY);
    if (!raw_kty) {
        throw std::invalid_argument("Missing key type");
    }

    auto kty = static_cast<cose_key_type>(static_cast<int64_t>(*raw_kty));
    spdlog::debug("Public key type: {}", get_cose_key_type_debug_description(kty));
    if (kty != cose_key_type::EC2) {
        throw std::invalid_argument(
            "Public key type {} is not supported"_format(get_cose_key_type_debug_description(kty))
        );
    }

    auto raw_alg = public_key_map.try_at<cbor_integer>(COSE_KEY_PARAMETER_ALG);
    if (!raw_alg) {
        throw std::invalid_argument("Missing key algorithm");
    }

    // ECDSA P-256 with SHA256 is the only algorithm supported by both OpenSSH
    // and Microsoft's WebAuthn API.
    auto alg = static_cast<cose_key_algorithm>(static_cast<int64_t>(*raw_alg));
    spdlog::debug("Public key algorithm: {}", get_cose_key_algorithm_debug_description(alg));
    if (alg != cose_key_algorithm::ECDSA_P256_WITH_SHA256) {
        throw std::invalid_argument(
            "Public key algorithm {} is not supported"_format(get_cose_key_algorithm_debug_description(alg))
        );
    }

    auto raw_crv = public_key_map.try_at<cbor_integer>(COSE_KEY_PARAMETER_EC2_CRV);
    if (!raw_crv) {
        throw std::invalid_argument("Missing EC2 curve type");
    }

    auto crv = static_cast<cose_ec2_curve_type>(static_cast<int64_t>(*raw_crv));
    spdlog::debug("Public key EC2 curve type: {}", get_cose_ec2_curve_type_debug_description(crv));
    if (crv != cose_ec2_curve_type::P256) {
        throw std::invalid_argument(
            "EC2 curve type {} is not consistent with other public key parameters"_format(
                get_cose_ec2_curve_type_debug_description(crv)
            )
        );
    }

    auto raw_x_coordinate = public_key_map.try_at<cbor_byte_string>(COSE_KEY_PARAMETER_EC2_X_COORD);
    if (!raw_x_coordinate) {
        throw std::invalid_argument("Missing EC2 curve X coordinate");
    }

    spdlog::debug("Public key EC2 curve X coordinate: {}", raw_x_coordinate->dump_debug());
    auto x_coordinate_bytes = *raw_x_coordinate;

    auto raw_y_coordinate = public_key_map.try_at(COSE_KEY_PARAMETER_EC2_Y_COORD);
    if (!raw_y_coordinate) {
        throw std::invalid_argument("Missing EC2 curve Y coordinate");
    }

    spdlog::debug("Public key EC2 curve Y coordinate: {}", raw_y_coordinate->dump_debug());

    // The WebAuthn spec doesn't permit for compressed elliptic point form; if
    // that form is used, the Y coordinate is encoded as a CBOR boolean value
    // indicating the sign bit. This type check isn't necessarily 100% accurate,
    // but we can't check for a boolean CBOR type because our implementation
    // doesn't support it (it's not used by us anywhere), but it's never correct
    // to _not_ have a byte vector here, so it'll do.
    if (raw_y_coordinate->type() != cbor_value_type::byte_string) {
        throw std::invalid_argument("EC2 compressed point form is not supported");
    }

    auto y_coordinate_bytes = raw_y_coordinate->get<byte_vector>();

    // Parsed everything correctly up until now. The WebAuthn spec explicitly
    // forbids having any additional optional parameters in the credential CBOR
    // object when working with EC2 public keys, so verify that constraint is
    // met.
    if (public_key_map.keys().size() != 5) {
        throw std::invalid_argument("Optional arguments in the public key data are not permitted");
    }

    binary_writer public_key_writer;

    // 0x04 indicates uncompressed elliptic curve coordinates, see:
    // https://tools.ietf.org/html/rfc5480#section-2.2.
    public_key_writer.write_uint8_t(0x04);
    public_key_writer.write_bytes(x_coordinate_bytes);
    public_key_writer.write_bytes(y_coordinate_bytes);

    byte_vector public_key_bytes = public_key_writer.vector();

    spdlog::debug("Public key parsed successfully");
    return public_key_bytes;
}

}  // namespace

}  // namespace wfb
