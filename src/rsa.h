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

/*
 * Methods
 */
char* 	I2OSP				(mpz_t x, int xLen);
void	OS2IP				(char *X, mpz_t x);
int		RSAEP				(struct RSAPublicKey *K, mpz_t m, mpz_t c);
int		RSADP				(struct	RSAPrivateKey *K, mpz_t c, mpz_t m);
char*	MGF1				(char *mgfSeed, unsigned long long maskLen);
char*	RSAES_OAEP_ENCRYPT	(struct RSAPublicKey *K, char *M, char *L);
char*	RSAES_OAEP_DECRYPT	(struct RSAPrivateKey *K, char *C, char *L);
