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
* Debian 11 (bullseye) running via [Windows Subsystem for Linux (WSL)
  2](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install)
* One of the following security keys:
  * YubiKey 4
  * YubiKey NEO
  * YubiKey 5 NFC

Other execution environments or security keys may work, but have not been
explicitly tested.

### Install Debian bullseye

Debian 10, the current release available in the Microsoft Store, does not have a
version of OpenSSH that's new enough to support FIDO keys. To get a version that
is new enough, you need to upgrade your base system to Debian 11 (bullseye). You
then need to install openssh-client from Debian sid to get the most recent
version.

To do that, install Debian from the Microsoft Store. Then, run the following
commands to upgrade your installation to bullseye:

```
cat << EOF | sudo tee /etc/apt/sources.list > /dev/null
deb http://deb.debian.org/debian bullseye main
deb http://security.debian.org/debian-security bullseye-security main
EOF

sudo apt update
sudo apt upgrade
sudo apt full-upgrade
sudo apt autoremove --purge
```

Finally, upgrade your version of openssh-client to the one from sid:

```
cat << EOF | sudo tee /etc/apt/sources.list.d/sid.list > /dev/null
deb http://deb.debian.org/debian sid main
EOF

cat << EOF | sudo tee /etc/apt/preferences.d/sid.pref > /dev/null
Package: *
Pin: release n=sid
Pin-Priority: 50
EOF

cat << EOF | sudo tee /etc/apt/preferences.d/openssh-client.pref > /dev/null
Package: openssh-client
Pin: release n=sid
Pin-Priority: 990
EOF

sudo apt update
sudo apt install openssh-client
```

Pulling openssh-client from sid is temporary until the package moves into
bullseye. Once it's available, you can remove the changes made above with the
following commands:

```
sudo rm /etc/apt/sources.list.d/sid.list /etc/apt/preferences.d/{sid,openssh-client}.pref
sudo apt update
```

### Build windows-fido-bridge from source

To build from source:

```
sudo apt install build-essential cmake g++-mingw-w64-x86-64 git libfmt-dev libgtest-dev

git clone https://github.com/mgbowen/windows-fido-bridge.git
cd windows-fido-bridge
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
