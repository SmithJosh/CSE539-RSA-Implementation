/*
 * Data Types
 */
struct RSAPublicKey {
    // modulus is a product of $u$ distinct odd primes $r_i$, $i=1,2,...,u$, where $u \geq 2$
	mpz_t modulus;
    // publicExponent is an integer between 3 and $modulus - 1$ satisfying $GCD(publicExponent, \lambda(modulus))$
	mpz_t publicExponent;
};

struct RSAPrivateKey {
    // modulus definition same as RSAPublicKey.modulus
	mpz_t modulus;
    // privateExponent is a positive int less than $n$ satisfying $e \cdot d \equiv 1 \pmod(\lambda(modulus))$
	mpz_t privateExponent;
};
