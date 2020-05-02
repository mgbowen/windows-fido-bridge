#pragma once

#include <windows.h>
#include <webauthn.h>

#include <memory>

namespace wfb {

struct webauthn_methods {
    decltype(&WebAuthNGetApiVersionNumber) GetApiVersionNumber;
    decltype(&WebAuthNAuthenticatorMakeCredential) AuthenticatorMakeCredential;
    decltype(&WebAuthNAuthenticatorGetAssertion) AuthenticatorGetAssertion;
    decltype(&WebAuthNGetErrorName) GetErrorName;
    decltype(&WebAuthNFreeAssertion) FreeAssertion;
    decltype(&WebAuthNFreeCredentialAttestation) FreeCredentialAttestation;
    std::shared_ptr<void> library_handle;

    static webauthn_methods load();
};

}  // namespace wfb
