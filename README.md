# Opsec (yes really) multi-tool
(Quick note: im not really into cybersecurity)
###
The opsec multi-tool is a tool designed for staying private on the internet with the following features:
- AES256 encrypted messages
- Decrypting AES256 messages

and more coming soon...
## Usage
### Encrypting
Encrypting messages is crutial when using a non-secured messaging platform. You can encrypt messages in using the following command
``` bash
opsec encrypt aes256 [insert message in quotes] [insert passkey in quotes]
```
### Decrypting
If your *partner in crime* has sent you a decrypted message, you can decrypt it like so:
``` bash
opsec decrypt aes256 [insert base64 phrase in quotes] [insert passkey in quotes]
```
## Installing (UNIX like systems)
### Pre-compiled binaries
You can obtain the pre-compiled binaries in the releases tab
### Self compilation
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