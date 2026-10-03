#1.1 
pbkdf2 turns your passphrase into the 256-bit AES key by running a hash function on it many times. Encrypting with a passphrase needs it because AES-256 needs a key that is exactly 256 random-looking bits, and the key derivation function stretches the passphrase into a proper key. 

#1.2 
The checksums are different because OpenSSL pics a new random salt everytime you encrypt, so each run gets a different key and IV. If the two encryptions were identical, then the attacker could learn things without ever decrypting. They can figure out if two messages are identical and guess the meanings. 

#1.3
1. ECB produces 3 distinct blocks and the most common one repeats 24 times. The CBC output shows 37 distinct blocks which each appear once. 
2. ECB encrypts every 16-byte block seperately with the same key. This leaks the structure of the data, showing which blocks are the same and how often they repeat. This matters to an attacker because they can spot patterns and repitition. If they guess the occurence or learn, they can match a ciphertext block into its plaintext.
3. A question I would ask is: "Where is the key stored and who can access it?"

#2.2
1. The SHA-256 does not protect my colleague because it has no secret, meaning anyone cam compute it including the attacker. The user checks the hash and they trust it if it matches the modified file, yet it could be the case that the attacker could change the file, compute SHA-256 of the modified file, or replace the hash with theirs if they have control over the channel. 
2. When you use an HMAC instead, a secret key that only my collegue and I know are mixed in. They key is necessary to compute a valid HMAC, so if my colleague recomputes the HMAC with the shared key and it doesn't match, we know it was tampered with. 
3. With SHA-256 only, the attacker can read and modify the file, produce a matching value for the modified file by recomputing the hash, get the modification accepted without detection, and block or delete the message. With HMAC, the attacker can read + modify the file, but it cannot produce a matching value for the modified file without the key and the modification cannot get accepted without detection. 

#3.3
1. This check proves that whoever uploaded the key could read email sent to dani.k@northeastern.edu at that moment, so they controlled that inbox. It doesn't really prove however that the person is actually me, as the name in the key isn't checked at all. They may also not be the righful owner of the account, as someone who hacked the account or an admin with access would also pass. It also doesn't prove that the private key is sept safe or hasn't been stolen, as this is just a check of control of an email address and not actual identity. 
2. The procedure would be to first compute the fingerprint of the key you just downloaded, then compare all 40 characters with the fingerprint my classmate reads to me through a channel the attacker can't control (like in-person or printed). If every character matches, then trust the key. This works because an attacker can't create a different key with the same fingerprint, so reading aloud the key face-to-face means that the attacker has no way to change what my classmate tells me, and it would be obvious if the attacker had swapped the key. 


#4.3
1. Signing users the signer's private key.
2. Verifying uses the signer's public key.
3. Encryption uses the recipient's public key. 
4. Decryption uses the recipient's private key.
5. Signing includes autenticity, which encryption doesn't include. It proves who created the message, and encryption anyone can encrypt with your public key, so an encrypted message tells you nothing about who sent it. 
#4.2
1. In each packet is a public-key ecrypted session key packet and the encrypted data packet is the compressed packet and the literal data packet.
2. RSA is a lot slower than AES, which makes encrypting a large file with RSA alone impractical. Secondly, there are size limits where RSA can only encrypt data smaller than its key size, so a longer message would have to be split into many RSA blocks which is slow and makes the output much bigger. 
3. Its called hybrid encryption. 

#5
The RSA and Ed25519 key sizes can't be compared directly as RSA relies on factoring large numbers, which has relatively efficient known attacks, so i tneeds very large keys to stay secure. Ed25519 relies on the elliptic curve discrete logarithmic problem which has no shortcut, so a 256-bit key gives about 128 bits of security, meaning a small key is just about as strong despite the size. 

# 7
Defect 1: There is no decrypt function so the GCM tag is never checked anywhere. For what an attacker could do, whoever writes the decryptor might skip or mishandle the check and accept a modified file. This defect violates Integrity / authentication. 
Defect 2: There are no password requirements, so an empty or shore password is accepted. This means the attacker could guess the password offline, since the salt is stored in the file. This violates key strength, because the key is only as strong as the passphrase.
Defect 3: PBKDF2 is not memory-hard, so an attacker could run guesses cheaply in parallel on GPUs. This violates key derivation concept.
Defect 4: The header has no format or version marker and isn't passed as associated data. This means the attacker could format confusion or downgrade if the format ever changes. This violates the concept of integrity of all data and not just the message.
Defect 5: The output is written with default permissions and not automatically, so the whole file is read into memeory. This means that other local users may be able to read the output, a crash can leave a partial file, or a huge file will exhaust memory. This violates the concept of availability / secure handling. 

#7.3
1. Added a decrypt_file function because the original could only encrypt, so a file could never be recovered and the GCM tag was never checked. This addresses the integrity problem as the tag is now verified before any plaintext is written, so a modified file or a wrong password is rejected.
2. Added a minimum password length of 12 characters because the original accepted any, even an empty one. This addresses the weak keys password as the AES key is only as strong as the password it comes from, so a short password could be guessed.
3. Replaced PBKDF2 with scrypt, as PBKDF2 uses very little memory so attackers can run many guesses in parallel on GPUs. This fix solves the brute force resistance issue because crypt makes large scale guessing a lot more expensive
4. Added a version marker and authenticated the header because the original file had no way to identify its format and the salt and nonce weren't explicity covered by the tag. This addreses the integrity issue of the whole file. 
5. Made file writing safer and added a size limit because the original wrote the output with default permissions. This fixes the confidentiality and availability issue as the output is now readable by only the owner and renamed into place once complete. 

When you run fixed_crypto.py, the output is: 
Round trip matches original: True
Wrong password rejected: Decryption failed: wrong password or modified file.

