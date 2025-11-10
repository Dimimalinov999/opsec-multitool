# Opsec (yes really) multi-tool
Now you can truly
```
sudo apt install opsec
```

(Quick note: im not really into cybersecurity)
###
The opsec multi-tool is a tool designed for staying private on the internet with the following features:
- AES256 encrypted messages
- Decrypting AES256 messages
- EXIF clean and wipe

and more coming soon...
## Usage
### Encrypting
Encrypting messages is crutial when using a non-secured messaging platform. You can encrypt messages in using the following command:
``` bash
opsec encrypt aes256 [insert message in quotes] [insert passkey in quotes]
```
### Decrypting
If your *partner in crime* has sent you a decrypted message, you can decrypt it like so:
``` bash
opsec decrypt aes256 [insert base64 phrase in quotes] [insert passkey in quotes]
```
### Cleaning EXIF data
if you have taken an image with your smartphone or digital camera, it leaves insecure info such as GPS location data and much more sensitive info. To clean the sensitive metadata and **preserve** technical data such as ISO, shutter speed, aperture etc. Use the following command:

**Tip:**
You can drag and drop the image in the terminal to fill the image path.
``` bash
opsec exif clean [image path]
```
### Wiping EXIF data
If you want to fully wipe the exif data for privacy reasons, use the following command:
``` bash
opsec exif wipe [image path]
```
## Installing (UNIX like systems)
### Pre-compiled binaries
You can obtain the pre-compiled binaries in the releases tab
### Self compilation
#### Dependencies
Sadly this software isn't dependency-less, so in order to compile the code yourself, you are gonna need the following dependencies:
- OpenSSL (for encryption)
- EXIV2 (for exif tools)

installing them:

(**NOTE:** you should install these even if you aren't compiling, just in case)
- **Debian based distros**
``` bash
apt-get install openssl libssl-dev libexiv2-dev exiv2
```
- **RPM based distros**
``` bash
dnf install openssl openssl-devel exiv2 exiv2-devel
```
- **Arch based distros**
```bash
pacman -S openssl exiv2
```
#### Actual compilation
You can compile the code yourself by running
``` bash
make
```
and/or install it via
``` bash
make install
```
or just run it via
``` bash
make run
```
## Installing (Windows) **(WIP)**
Im not quite familiar with minGW, so if you have experience, please inform me.