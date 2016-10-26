/*
 * BigInt.h
 *
 *  Created on: Oct 13, 2016
 *      Author: Joshua
 */

#ifndef BIGINT_H_
#define BIGINT_H_

#define max(A,B) ((A)>(B) ? (A) : (B))

/*
 * Data Types
 */
typedef struct {				// Arbitrary precision decimal integer
	unsigned char * val;
	unsigned short size;
} BigInt;

/*
 * BigInt Operations
 */
BigInt* 	NewBigInt		(char * val);
void 		FreeBigInt		(BigInt * x);
char* 		BigIntToString	(BigInt * x);
int 		Equal			(BigInt * x, BigInt * y);
int 		GTEqual			(BigInt * x, BigInt * y);
BigInt*		Add				(BigInt * x, BigInt * y);
BigInt*		Subtract		(BigInt * x, BigInt * y);
BigInt*		Mult			(BigInt * x, BigInt * y);
BigInt*		Mult_10ToM		(BigInt * x, unsigned int M);
BigInt*		Mult_Digit		(BigInt * x, unsigned char y);
BigInt*		Mod				(BigInt * x, BigInt * y);
BigInt*		ModPow			(BigInt * x, BigInt * e, BigInt * n);

BigInt*		RandBigInt		(unsigned short bits);

/*
 * Utility Methods
 */
unsigned long modPow(unsigned long base, unsigned long exp, unsigned long mod);

#endif /* BIGINT_H_ */
