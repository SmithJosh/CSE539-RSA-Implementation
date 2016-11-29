#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "rsa.h"

int Test1(struct RSAPublicKey*, struct RSAPrivateKey*);

int main() {
    int nlen = 1024;
	struct RSAPublicKey pubK;
	struct RSAPrivateKey privK;
	mpz_init(pubK.modulus);
	mpz_init(pubK.publicExponent);
	mpz_init(privK.modulus);
	mpz_init(privK.privateExponent);

    mpz_t e, p, q, d, n;
    mpz_init(e); mpz_init(p); mpz_init(q); mpz_init(d); mpz_init(n);
    gen_e(e);
    gen_auxiliary_primes(p, e, nlen);
    gen_auxiliary_primes(q, e, nlen);
    mpz_mul(n, p, q);

    unsigned long int one = 1;
    mpz_t pm1, qm1;
    mpz_init(pm1); mpz_init(qm1);
    mpz_sub_ui(pm1, p, one);
    mpz_sub_ui(qm1, q, one);
    gen_d(d, pm1, qm1, e, nlen);

    mpz_set(pubK.modulus, n);
    mpz_set(pubK.publicExponent, e);

    mpz_set(privK.modulus, n);
    mpz_set(privK.privateExponent, d);

	if (Test1(&pubK, &privK))
		printf("Test1: Passed!\n");
	else
		printf("Test2: Failed!\n");

	return 0;
} 

int Test1(struct RSAPublicKey *pubK, struct RSAPrivateKey *privK) {
	char *message = "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34";
	char *mStr = "a8 b3 b2 84 af 8e b5 0b 38 70 34 a8 60 f1 46 c4 91 9f 31 87 63 cd 6c 55 98 c8 ae 48 11 a1 e0 ab c4 c7 e0 b0 82 d6 93 a5 e7 fc ed 67 5c f4 66 85 12 77 2c 0c bc 64 a7 42 c6 c6 30 f5 33 c8 cc 72 f6 2a e8 33 c4 0b f2 58 42 e9 84 bb 78 bd bf 97 c0 10 7d 55 bd b6 62 f5 c4 e0 fa b9 84 5c b5 14 8e f7 39 2d d3 aa ff 93 ae 1e 6b 66 7b b3 d4 24 76 16 d4 f5 ba 10 d4 cf d2 26 de 88 d3 9f 16 fb";
	char *eStr = "01 00 01";
	char *dStr = "53 33 9c fd b7 9f c8 46 6a 65 5c 73 16 ac a8 5c 55 fd 8f 6d d8 98 fd af 11 95 17 ef 4f 52 e8 fd 8e 25 8d f9 3f ee 18 0f a0 e4 ab 29 69 3c d8 3b 15 2a 55 3d 4a c4 d1 81 2b 8b 9f a5 af 0e 7f 55 fe 73 04 df 41 57 09 26 f3 31 1f 15 c4 d6 5a 73 2c 48 31 16 ee 3d 3d 2d 0a f3 54 9a d9 bf 7c bf b7 8a d8 84 f8 4d 5b eb 04 72 4d c7 36 9b 31 de f3 7d 0c f5 39 e9 cf cd d3 de 65 37 29 ea d5 d1";

    /*
	mpz_set_str(pubK->modulus, mStr, 16);
	mpz_set(privK->modulus, pubK->modulus);
	mpz_set_str(pubK->publicExponent, eStr, 16);
	mpz_set_str(privK->privateExponent, dStr, 16);
    */
	
	char *C = RSAES_OAEP_ENCRYPT(pubK, message, NULL);
	char *M = RSAES_OAEP_DECRYPT(privK, C, NULL);
	if (!M) return -1;

    printf("%s%s\n\n%s%s\n\n%s%s\n\n","M: ", message, "C: ", C, "Decrypted M: ", M); 
	
	return (strcmp(M, message) == 0);
}
