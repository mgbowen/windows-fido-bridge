# windows-fido-bridge

## Install

### Clone the repository

```
cd ~
git clone git@github.com:mgbowen/windows-fido-bridge.git
```

### Build openssh-client from source

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
Dockerfile provided by this package with the following commands:

```
# Or wherever you cloned the repository
cd ~/windows-fido-bridge

cd openssh-client
docker build -t windows-fido-bridge-openssh-client .

mkdir build
cd build
docker run --rm -it -v "$(pwd):/build" windows-fido-bridge-openssh-client /openssh-client/build-package
sudo dpkg -i openssh-client_8.2p1-4_amd64.deb
```

**Note that this may result in your SSH client breaking in strange and/or
mysterious ways!** I will not be held responsible if you, for example, need to
reinstall your Debian installation.

(Optional) You can clean up created the Docker image with the following command:

```
docker rmi windows-fido-bridge-openssh-client
```

### Build windows-fido-bridge from source

Currently, this package is tested using Debian "buster" via WSL2 on Windows 10
version 2004 (build 19041).

To build from source:

```
sudo apt install build-essential cmake g++-mingw-w64-x86-64 libfmt-dev libgtest-dev

# Or wherever you cloned the repository
cd ~/windows-fido-bridge
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j $(nproc)
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
