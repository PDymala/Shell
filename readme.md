# SHELL - simple file encryption for secure sharing

## What is this about?

Imagine John wants to send Bob a private file. They both do not have any PGP or any other commercial software. Using ZIP with a password is inconvinient as they would have to send the password via other media like phone.
Those are also susceptible for hacking (passwords not ZIP). 
How to use SHELL for this purpose?
- Bob generates a key pair and send the public one to John
- John loads the public key and the file to be encrypted to the software. Next, he encrypts it.
- John can send the file to Bob via public network e.g. e-mail
- Bob loads the private key and the encrypted file to the software. Next, he can decrypt it.
- The file has been transferred. 


## What happens behind the scenes?
The file is encrypted via AES 256 bit with a random password. The password is then encrypted by RSA 4k public-private. 
When encrypting, the password is added to the encrypted file. During decryption, the password is firstly separated from the main file and then decrypted with RSA key. 
Later, the main file is decrypted with the decrypted password.

## TECH
JAVA + JAVAFX

## LICENSE 
FREE TO USE

## DISCLAIMER
I am not an IT security expert. This was just a hobby project. Use at own risk.