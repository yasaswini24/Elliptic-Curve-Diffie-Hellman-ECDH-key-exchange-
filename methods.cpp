#define LTM_DESC
#define USE_LTM
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <tomcrypt.h>
#include <string>
#include <math.h>
// If you get any errors about LTM, please download / install ltommath and re-make libtomcrypt with configuration

// This function takes in a prng_state & initializes it
// Example usage: prng = make_prng(&prng);
prng_state make_prng(prng_state *prng) {
   std::string s_str = "a totally secure and random string";
   int err;
   if (register_prng(&chacha20_prng_desc) == -1) {
      printf("Error registering Yarrow\n");
      exit(-1);
   }
   /* setup the PRNG */
   if ((err = rng_make_prng(128, find_prng("chacha20"), prng, NULL)) 
       != CRYPT_OK) {
      printf("Error setting up PRNG, %s\n", error_to_string(err));
      exit(-1);
   }
   chacha20_prng_add_entropy((const unsigned char*)s_str.c_str(), s_str.size(), prng);
   return *prng;
}

// ecc_key will hold both the private and public key after calling ecc_make_key
// Example of usage: ecc_key* alice_key = make_pk_sk_pair(prng);
ecc_key make_pk_sk_pair(prng_state prng) {
   int err;
   ecc_key* key = (ecc_key*)malloc(sizeof(ecc_key));
   if(!key) {
      printf("Malloc error");
      exit(-1);
   }

   // Make public/private key pair
    if ((err = ecc_make_key(&prng, find_prng("chacha20"), 32, key)) != CRYPT_OK) {
      printf("Error making key: %s\n", error_to_string(err));
      exit(-1);
   }
   return *key;
}

// Exports the public key into a unsigned char* (which we can transfer with zeromq)
// This function updates the values it was given
// The length is important for when you want to import! This function changes the length
// Example call: export_public_key(alice_key, &alice_length, alice_out_pk_exp);
void export_public_key(ecc_key key, unsigned long* outlen, unsigned char* out) {
   int err;
   if(err = ecc_export(out, outlen, PK_PUBLIC, &key) != CRYPT_OK) {
      printf("Error exporting key: %s\n", error_to_string(err));
      exit(-1);
   }
   // We do not return anything because we are updating the outlen and out parameters.
}

// This takes a unsigned char* (an exported public key) and it's length
// And returns it in ecc_key form
// Example usage: ecc_key bob_public_key = import_public_key(bob_length, bob_out_pk_exp);
ecc_key import_public_key(unsigned long outlen, unsigned char* out) {
   // Import exported keys
   int err;
   ecc_key* key = (ecc_key*)malloc(sizeof(ecc_key));
   if(!key) {
      printf("Error with malloc");
      exit(-1);
   }
   if(err = ecc_import(out, outlen, key) != CRYPT_OK) {
      printf("Error exporting key: %s\n", error_to_string(err));
      exit(-1);
   }
   return *key;
}

// Create a shared key 
// Puts the shared secret into out, and changes the value length to reflect out's length
// Example:    compute_shared_secret(bob_key, alice_public_key, bob_secret, &bob_secret_length);

void compute_shared_secret(ecc_key private_key, ecc_key public_key, unsigned char* out, unsigned long* length) {
   int err;
   // compute shared secrets
   if(err = ecc_shared_secret(&private_key, &public_key, out, length) != CRYPT_OK) {
      printf("Error calculating shared key");
   }
}

// HMAC function for the handshake phase
// Read in message from a file, and the key* should be the shared secret
// After, declare unsigned char[32] mac, and send a pointer to it (&mac) to this function.
// The function updates its value. 
void HMAC_Computation(char *message, unsigned char *mac, unsigned char *key)
{
    int idx;
    hmac_state hmac;
    unsigned char dst[64];
    unsigned long dstlen;
    register_hash(&sha256_desc);
    idx = find_hash("sha256");
    hmac_init(&hmac, idx, key, 32);
    hmac_process(&hmac, (const unsigned char*) message, sizeof(message));
    dstlen = sizeof(dst);
    hmac_done(&hmac, dst, &dstlen);
    memcpy(mac, dst, dstlen);
}