# mySSL
The goal of your program is to build your own simplified version of SSL, called mySSL, in Java or Python. Use client server sockets to create a TCP connection. Also, use the SSL record format for both your handshake and data phase messages. Your client server programs must do the following:

Handshake Phase
---------------
• The client and the server authenticate each other using certificates. You need to create the certificates (self-signed) and include them in the mySSL messages.
• The client also informs the server what data encryption and integrity protection scheme to use (there is no negotiation). Pick your favorite integrity protection and encryption algorithms.
• The client and server also send encrypted nonces to each other encrypted with the other side’s public key (the public keys are obtained from the certificates). These nonces are then xored to create a master secret.
• Compute a hash of all messages exchanged at both the client and server and exchange these hashes. Use keyed SHA-1 for computing the hash. The client appends the string CLIENT for computing its keyed hash and the server appends the string SERVER for computing its keyed hash. Verify the keyed hashes at the client and the server.
• Generate four keys (two each for encryption, authentication, in each direction of the communication between the client and the server) using this master secret. Pick your own key generation function (should be a function of the master secret). You can use a hash function, if you like.

Data Phase
----------
• Transfer a file, at least 50 Kbytes long, from the server to client.
• Decrypt the file at the client and do a diff of the original and the decrypted file to ensure that the secure file transfer was successful.

Use opnessl or any other security library of your choice in any form convenient to you to
generate certificates and to extract public keys from certificates and also for keyed hash
computation, encryption, and data integrity protection.
Include print commands in your code to show
1. a failed verification of keyed hashes (possibly due to corruption or changes in one of
the handshake messages), and
2. a successful client-server mutual authentication, key establishment, and secure data
transfer.


The code files are present in the current folder and the "...\General\General.java" contains the package that I imported in my files to reuse the code.

Files in current folder:
-----------------------
Alice.java -> This file represents Alice and her behavior in mySSL.
Bob.java -> This file represents Bob and his behavior in mySSL.
CA.java -> This file represents CA's behavior in mySSL.

Files in "...\General\General.java":
------------------------------------
General.java -> This file contains the reusable code used in the project.


To implement mySSL:
-------------------
> Navigate to "...\PA2" folder and import the folder into IDE.
> First run CA.java
> Next, run Bob.java
> Next, run Alice.java
