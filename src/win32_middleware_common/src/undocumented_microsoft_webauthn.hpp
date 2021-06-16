#pragma once

//
// This header contains parameters that can be passed to Microsoft's WebAuthn
// API, but are not present in official documentation.
//

// This value comes from the COSE list maintained by IANA:
// https://www.iana.org/assignments/cose/cose.xhtml
#define WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519 -8
