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
 * Methods for Generating Key Pairs
 */

void    gen_e               (mpz_t e);
void    gen_d               (mpz_t d, mpz_t p_minus_1, mpz_t q_minus_1, mpz_t e, int n);
void    gen_probable_prime  (mpz_t p, mpz_t p1, mpz_t p2, mpz_t e, int n);
void    gen_primes          (mpz_t p, mpz_t e, int n);
int     coprime             (mpz_t a, mpz_t b);


/*
 * Methods for Encryption and Decryption
 */
char* 	I2OSP				(mpz_t x, int xLen);
void	OS2IP				(char *X, mpz_t x);
int		RSAEP				(struct RSAPublicKey *K, mpz_t m, mpz_t c);
int		RSADP				(struct	RSAPrivateKey *K, mpz_t c, mpz_t m);
char*	MGF1				(char *mgfSeed, unsigned long long maskLen);
char*	RSAES_OAEP_ENCRYPT	(struct RSAPublicKey *K, char *M, char *L);
char*	RSAES_OAEP_DECRYPT	(struct RSAPrivateKey *K, char *C, char *L);
