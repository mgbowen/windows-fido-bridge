#include "webauthn_linking.hpp"
#include "windows_error.hpp"
#include "windows_fwd.hpp"
#include "windows_util.hpp"

#include <windows_fido_bridge/format.hpp>

#include <iostream>

namespace wfb {

namespace {

template <typename T>
T get_proc_address(HINSTANCE library, const char* method_name) {
    auto result = reinterpret_cast<T>(GetProcAddress(library, method_name));
    if (result == nullptr) {
        throw_windows_exception("Failed to find method {}"_format(method_name));
    }

    return result;
}

}  // namespace

webauthn_methods webauthn_methods::load() {
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

}  // namespace wfb
