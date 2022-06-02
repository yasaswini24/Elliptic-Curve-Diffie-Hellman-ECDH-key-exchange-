# Elliptic-Curve-Diffie-Hellman-ECDH-key-exchange-

_**Key Generation Phase**_
1. For libtomcrypt’s library, it uses a pseudo-random number generator. Initialize the PRNG using the function provided.
2. Both Alice and Bob should make a private/public key pair, using the function provided. 	
3. Afterwards, they should export the public key and the length so that it is usable for the next phase (using the function provided). They should never send the private key, or else they compromise secrecy.

_**Key Exchange**_
1. Using ZeroMQ, transfer Alice and Bob’s keys to each other (and the lengths). There’s a demo  for ZeroMQ that shows how to transfer integers over (ZeroMQ does not natively support this).
2. After Bob and Alice receive each other’s keys, and use the import function (provided) to convert into libtomcrypt’s recognized ecc_key form.
3. Now, Bob and Alice should have their respective private key, and the other’s public key. Using the provided function, they will generate a shared key K. Ideally, this could either be used for encryption or authentication at this point. In section 8 of the libtomcrypt documentation, you can read more about how these are used.

_**Handshake/Confirmation**_

The handshake protocol ensures that both parties successfully derived the same key, without disclosing keys to each other. For this purpose, Alice takes an input R from a handshake.txr file, and computes an HMAC on it as h_alice = HMAC_K(R), and send it to Bob over ZeroMQ. Bob verifies this HMAC by using private key K.  It should print something like, “Verified” if successful, or print an error if not.
