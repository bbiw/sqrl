
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

I implemented a similar idea for sqrl.crypto.Nonce, but I am not sure I like it.
The only advantage it has over a random nonce is that it may be slightly faster.

For block type 2, a zero nonce is OK because the
key is the EnScrypted rescue code, which changes exactly whenever a new IUK/IMK is created.

For block type 3, a zero nonce is OK because the encryption key is the IMK, which changes exactly whenever
a new UIK is generated and the old one is added to block 3.

## Consider memorizing generated passwords

### RescueCode

From https://www.grc.com/sqrl/key-flow.htm

> Simple decimal digits were chosen because they are simple, are more language-neutral than alphabetic symbols, and are typically easier to enter than special characters. Although larger character sets using case-sensitive alphabetic and special symbols encode a larger number of bits per symbol, human factors studies show that, to obtain a desired total bit length representation, ease of use increases as the size of the character set is reduced and the number of characters is increasing. In other words, people would rather enter a greater number of simple characters than fewer complex characters.

My experience is different. I would much rather memorize 9 (3 groups of 3) short words (90 bits from EFF's short word diceware list) than 6 meaningless 4-digit numbers (80 bits). Steve is expecting people to write down the rescue code on paper.  While that is not unreasonable, it is less convenient and less secure than memorizing it. (Consider jurisdictions where a memorized password is protected under something like the 5th amendment, but a written document is not.)

The key to memorizing these high-entropy passwords is spaced repetition.  Creating
a new identity should be done infrequently, so it is reasonable to expect it is
done in a secure environment (e.g. air-gapped Raspberry Pi running a hardened Alpine Linux).

  * Include the SRS functionality with the SQRL app.
  * Generate or have the user choose/write down a 'week' (a.k.a. weak) password.
  * Encrypt the strong password under the week password
  * Follow the SRS schedule to memorize the strong password
  * After a week, the week password can be retired and the encrypted strong password overwritten.
  * Continue repetition of strong password at increasing intervals. After a few months, the password will be unforgettable.

The SRS block with the week password SHOULD stay on the hardened computer, and SHOULD NOT be transfered to a less secure platform.

Considering something similar to the hint strategy, it might be reasonable for the week password to be the first word or two of the strong password. After the first day, it could be increased to 3, 4, and 5 words.

In any case, SRS would work just as well to memorize the 24-digit code, which *is* easier to *type*.
