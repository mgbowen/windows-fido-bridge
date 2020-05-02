# windows-fido-bridge

This repository implements [an OpenSSH SK
middleware](https://github.com/openssh/openssh-portable/blob/e9dc9863723e111ae05e353d69df857f0169544a/PROTOCOL.u2f)
that allows you to use [a FIDO/U2F security
key](https://en.wikipedia.org/wiki/Universal_2nd_Factor) (for example, [a
YubiKey](https://www.yubico.com/products/)) to SSH into a remote server from a
machine running Windows 10 via [Windows Subsystem for
Linux](https://docs.microsoft.com/en-us/windows/wsl/about).

## Install

This package has been tested with the following setup:

* Windows 10 version 2004 (>= build 19041)
* Debian 10.0 "buster" running via [Windows Subsystem for Linux (WSL)
  2](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install)
* One of the following security keys:
  * YubiKey 4
  * YubiKey NEO
  * YubiKey 5 NFC

Other execution environments or security keys may work, but have not been
explicitly tested.

### Clone the repository

```
cd ~
git clone https://github.com/mgbowen/windows-fido-bridge.git
```

### Build openssh-client from source

**Note that the following may result in your Debian installation breaking in
strange and/or mysterious ways!** I will not be held responsible if you end up
needing to recreate your WSL2 Debian installation.

Unfortunately, the SK API that OpenSSH provides is not directly compatible with
Windows' WebAuthN API; specifically, when obtaining an assertion with a
previously-made credential, OpenSSH provides SK middlewares with a challenge
string that has already been SHA256 hashed, whereas Windows requires that you
provide it the preimage of that challenge string which is then hashed by the
WebAuthN API before being passed to the security key. There are API changes in
OpenSSH master (see
[commit](https://github.com/openssh/openssh-portable/commit/59d2de956ed29aa5565ed5e5947a7abdb27ac013),
among others) that pass the preimage instead of the hash, but until those
changes can be propagated into an official release, you must build the OpenSSH
client from source.

To build an OpenSSH client with the required API changes, you can use a
Dockerfile provided by this package. You'll need a Docker Desktop version with
WSL2 support installed for Docker to work inside your WSL2 distro; currently,
that's Docker Desktop for Windows (Edge), see
[here](https://hub.docker.com/editions/community/docker-ce-desktop-windows).

Once Docker is working, use the following to build and install OpenSSH:

```
# Or wherever you cloned the repository
cd ~/windows-fido-bridge

cd openssh-client
docker build -t windows-fido-bridge-openssh-client .

mkdir build
cd build
docker run --rm -it -v "$(pwd):/build" windows-fido-bridge-openssh-client /openssh-client/build-package
```

Then, you'll need to source libfido from the Debian "bullseye" repositories,
which you can do by running the following commands:

```
cat << EOF | sudo tee /etc/apt/preferences.d/package-libfido2.pref > /dev/null
Package: libfido2-1
Pin: release a=bullseye
Pin-Priority: 980

Package: libfido2-1
Pin: release a=bullseye-security
Pin-Priority: 990

Package: *
Pin: release a=bullseye
Pin-Priority: 200

Package: *
Pin: release a=testing
Pin-Priority: 200

Package: *
Pin: release a=bullseye-security
Pin-Priority: 210

Package: *
Pin: release a=testing-security
Pin-Priority: 210
EOF

cat << EOF | sudo tee /etc/apt/sources.list.d/bullseye.list > /dev/null
deb http://deb.debian.org/debian bullseye main
deb http://security.debian.org/debian-security bullseye-security main
EOF

sudo apt update
```

Finally, install your custom-built OpenSSH client:

```
sudo apt install ./openssh-client_8.2p1-4_amd64.deb
```

(Optional) You can clean up created the Docker image with the following command:

```
docker rmi windows-fido-bridge-openssh-client
```

### Build windows-fido-bridge from source

To build from source:

```
sudo apt install build-essential cmake g++-mingw-w64-x86-64 libfmt-dev libgtest-dev

# Or wherever you cloned the repository
cd ~/windows-fido-bridge
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j $(nproc)
make test
sudo make install
```

## Use

First, you need to generate a key tied to your FIDO/U2F-compliant security key.
To do that, you need to tell OpenSSH what middleware library to use. If you used
the installation instructions above, you can use the following command:

```
SSH_SK_PROVIDER=/usr/local/lib/libwindowsfidobridge.so ssh-keygen -t ecdsa-sk
```

If everything goes well, you should see a Windows dialog pop up asking you to
use your security key. After you confirm and tap your security key, OpenSSH
should then write a public/private key pair to disk. After adding the public key
to your remote server's `.ssh/authorized_keys` file, you can then authenticate
using the following command:

```
ssh -oSecurityKeyProvider=/usr/local/lib/libwindowsfidobridge.so remote-server
```

You should now be logged in to your remote server!

## References

* [Web Authentication: An API for accessing Public Key Credentials, Level
  1](https://www.w3.org/TR/webauthn/)
  * The official W3C WebAuthN specification. Microsoft's API seems to be largely
    based directly on this document.
* [U2F support in OpenSSH
  HEAD](https://marc.info/?l=openssh-unix-dev&m=157259802529972&w=2)
  * Email by Damien Miller announcing the release of OpenSSH's U2F/FIDO support.
