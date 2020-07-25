# windows-fido-bridge

This repository implements [an OpenSSH security key
middleware](https://github.com/openssh/openssh-portable/blob/e9dc9863723e111ae05e353d69df857f0169544a/PROTOCOL.u2f)
that allows you to use [a FIDO/U2F security
key](https://en.wikipedia.org/wiki/Universal_2nd_Factor) (for example, [a
YubiKey](https://www.yubico.com/products/)) to SSH into a remote server from a
machine running Windows 10 and [Windows Subsystem for
Linux](https://docs.microsoft.com/en-us/windows/wsl/about).

## Requirements

At a minimum, you must have the following in order to use this repository:

* A local Linux distribution running inside WSL with OpenSSH 8.3 or newer
  installed.
  * An earlier version of OpenSSH will not work because of an incompatibility
    with Microsoft's WebAuthn API.
* A remote server running OpenSSH 8.2 or newer.
  * The aforementioned API incompatibility does not affect the remote server, so
    it **does not** need OpenSSH 8.3.
* A FIDO/U2F security key.

## Install

This repository has been tested with the following setup:

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
is new enough, you need to upgrade your base system to Debian 11 (bullseye).

To do that, install Debian from the Microsoft Store, then run the following
commands to upgrade your installation to bullseye:

```
sudo mv /etc/apt/sources.list /etc/apt/sources.list.orig
cat << EOF | sudo tee /etc/apt/sources.list > /dev/null
deb http://deb.debian.org/debian bullseye main
deb http://security.debian.org/debian-security bullseye-security main
EOF

sudo apt update
sudo apt upgrade
sudo apt full-upgrade
sudo apt autoremove --purge
```

Pulling openssh-client from sid was previously needed, but the package has since
moved directly into bullseye. You can remove the changes you had made with the
following commands:

```
sudo rm /etc/apt/sources.list.d/sid.list /etc/apt/preferences.d/{sid,openssh-client}.pref
sudo apt update
```

### Build from source

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

There is also the option of packaging the built binaries into a deb package and
installing that package instead of using `make install`:

```
sudo apt install debhelper

make package
sudo apt install ./windows-fido-bridge_*_*.deb
```

Note that if you install the deb package, apt will place the built binaries in
`/usr/lib`, whereas `make install` will place them, by default, in
`/usr/local/lib`. The distinction is important to remember when you set the
`SecurityKeyProvider` option when calling `ssh` or the `SSH_SK_PROVIDER`
environment variable.

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

## Tips

### Using with ssh-agent

If you want to use a security key-backed SSH key with `ssh-agent`, you should
make sure to either invoke `ssh-add` with the `-S` argument pointing to
`libwindowsfidobridge.so` or set the `SSH_SK_PROVIDER` environment variable
before calling `ssh-add`. Note that you **must** specify the full path to the
library when passing it to `ssh-add` for `ssh-agent` to accept it. For example:

```
ssh-add -S /usr/local/lib/libwindowsfidobridge.so

# or

SSH_SK_PROVIDER=/usr/local/lib/libwindowsfidobridge.so ssh-add
```

You may also completely omit the explicit library specification if you place the
`SSH_SK_PROVIDER` environment variable definition in your `.bashrc` or whatever
your shell's equivalent file is.

### Using from Windows

If you want to be able to run `ssh` from a Windows command prompt without first
being in a WSL prompt, you can create a directory somewhere on your Windows
filesystem (for example, `C:\Users\<username>\bin`), add that directory to your
`PATH`, and create a file inside that directory named `ssh.bat` with the
following contents:

```
@wsl ssh %*
```

If the WSL distribution you installed windows-fido-bridge in is not your
default, be sure to pass the `--distribution` argument to `wsl` specifying the
name of the appropriate distribution. Also be sure that you don't have the
Microsoft-distributed OpenSSH client installed or that one may be used instead
of the WSL one.

## References

* [Web Authentication: An API for accessing Public Key Credentials, Level
  1](https://www.w3.org/TR/webauthn/)
  * The official W3C WebAuthn specification. Microsoft's API seems to be largely
    based directly on this document.
* [U2F support in OpenSSH
  HEAD](https://marc.info/?l=openssh-unix-dev&m=157259802529972&w=2)
  * Email by Damien Miller announcing the release of OpenSSH's U2F/FIDO support.
