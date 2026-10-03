#Part 6 

# Puzzle 1
 Plain text: I got a jar of dirt
Operation chain:
1. Vigenere Decode, key "dirt" (direction: decode)
2. Substitute, QWERTY keyboard order -> normal alphabet (direction: decode)
    - Plaintext field: qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM
    - Ciphertext field: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
3. From Base64 (direction: decode_
4. From Binary, space delimiter, byte length 8 (direction: decode)

#Puzzle 2
Plain text: NOT ALL TREASURES SILVER AND GOLD MATE

Operation chain:
1. Mono-alphabetic substitution using the key in Crypto.jpeg 
   ( C=0, E=3, R=4, I=5, S=6, F=7, U=8, N=9) - direction: decrypt
2. Caesar Box cipher, box width 5, space kept - direction: decrypt
3. SMS  code - direction: decrypt
4. Atbash cipher - rection: decrypt (same operation both ways)
