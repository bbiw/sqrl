
# Implementation Notes

These express questions, problems, and solutions I came up with while studying
and implementing the so-called spec.


## S4 Storage

### AES-GCM

sodium's implementation only works on recent Intel processors, and the currently
(2016) widely-deployed version (1.0.8) doesn't include it.


> Support for AES256-GCM was introduced in Libsodium 1.0.4.

> The detached API was introduced in Libsodium 1.0.9.

PyCrypto does include
an implementation if you dig in to the hazmat packages. I'll have to get my code
reviewed.

For interoperability, using it is definitely necessary, even though using
sodium's `crypto_aead_chacha20poly1305_*()` would be easier.

https://download.libsodium.org/doc/secret-key_cryptography/chacha20-poly1305.html


### Nonce length

From https://download.libsodium.org/doc/secret-key_cryptography/aes-256-gcm.html

> The nonce is 96 bits long. In order to prevent nonce reuse, if a key is being reused, it is recommended to increment the previous nonce instead of generating a random nonce for each message. To prevent nonce reuse in a client-server protocol, either use different keys for each direction, or make sure that a bit is masked in one direction, and set in the other.

> It is recommended to split message larger than 2 Gb into smaller chunks.

The first figure at https://www.grc.com/sqrl/storage.htm incorrectly identifies
the AES-GCM IV as being 16 bytes.  If it were so, `pt length` would be 49 and
`length` would be 129.  Twelve bytes (96-bits) is a pretty short nonce. If you pass a nonce longer or shorter than 12 bytes, the code hashes it.  The real IV is 16 bytes, and the code uses 4 bytes for counting blocks,
giving, in this case, 4 billion 16-byte blocks before it repeats.  This is serious
overkill in our case, as we are only processing 7 blocks (adlen+ctlen=45+64=109 bytes). Therefore, I don't think it would hurt to use a 16-byte nonce.


Another approach would be to give each application instance a unique identifier and
mix it with counter that gets incremented every time that app encrypts a type 1
block. How to make the app-id unique? *Maybe* ask the user.

For block type 2, a zero nonce is OK because the
key is the EnScrypted rescue code, which changes exactly whenever a new IUK/IMK is created.

For block type 3, a zero nonce is OK because the encryption key is the IMK, which changes exactly whenever
a new UIK is generated and the old one is added to block 3.
