/*
 * Data Types
 */
struct RSAPublicKey {
	mpz_t modulus;
	mpz_t publicExponent;
};

struct RSAPrivateKey {
	mpz_t modulus;
	mpz_t privateExponent;
};
