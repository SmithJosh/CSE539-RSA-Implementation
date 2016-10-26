#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include "BigInt.h"

int main()
{
	BigInt * bi1 = NewBigInt("68636564122675662743823714992884378001308422399791648446212449933215410614414642667938213644208420192054999687");
	BigInt * bi2 = NewBigInt("32929074394863498120493015492129352919164551965362339524626860511692903493094652463337824866390738191765712603");
	BigInt * result;

	clock_t tic = clock();
	if ((result = Mod(bi1, bi2)))
		puts(BigIntToString(result));
	else
		puts("Output NULL");
	clock_t toc = clock();
	printf("Elapsed: %f seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC);

	free(bi1);
	free(bi2);
	return 0;
}

// Initialize new BigInt from integer string. Storage format is little-endian.
// If input string is empty, value is assigned to be 0.
BigInt * NewBigInt(char * s) {
	int i, size;
	int length = strlen(s);
	int zeros = 0;

	// Skip 0's at front of input string
	while (s[zeros] == '0')
		++zeros;
	size = max(length - zeros, 1);	// Length of integer can't be 0

	// Initialize new BigInt
	BigInt* bigint = malloc(sizeof(BigInt));
	bigint->val	= malloc(size * sizeof(unsigned char));
	bigint->size = size;

	// If there are no non-zero digits, assign value of 0
	if (length == zeros)
		bigint->val[0] = 0;
	else {
		for (i = 0; i < size; ++i)
			bigint->val[i] = s[zeros + size - i - 1] - '0';
	}

	return bigint;
}

// Cleanup BigInt memory
void FreeBigInt(BigInt * x) {
	free(x->val);
	free(x);
}

// Convert BigInt to decimal string
char * BigIntToString(BigInt * x) {
	int i;
	int size = x->size;
	char * s = malloc(size * sizeof(unsigned char) + 1);

	for (i = 0; i < size; ++i)
		s[i] = x->val[size - i - 1] + '0';
	s[size] = '\0';

	return s;
}

// If x == y, return 1. Otherwise, return 0.
int Equal(BigInt * x, BigInt * y) {
	if (x->size != y->size)
		return 0;

	int i;
	for (i = 0; i < x->size; ++i)
		if (x->val[i] != y->val[i])
			return 0;

	return 1;
}

// If x >= y, return 1. Otherwise, return 0.
int GTEqual(BigInt * x, BigInt * y) {
	int xsize = x->size;
	int ysize = y->size;

	if (xsize < ysize) return 0;
	if (xsize > ysize) return 1;

	int i = xsize, x_i, y_i;
	while (i-- > 0) {
		x_i = x->val[i];
		y_i = y->val[i];
		if (x_i < y_i) return 0;
		if (x_i > y_i) return 1;
	}

	return 1;
}

// Add x and y. Given m = max(xsize, ysize), result is of size m or m+1.
BigInt * Add(BigInt * x, BigInt * y) {
	BigInt * tmp;

	// Swap pointers so that xsize >= ysize
	if (x->size < y->size) {
		tmp = x;
		x = y;
		y = tmp;
	}

	int xsize = x->size;
	int ysize = y->size;
	BigInt * sum = malloc(sizeof(BigInt));
	sum->val = malloc((xsize + 1) * sizeof(BigInt));

	// Add last ysize digits of x and y
	int i, r = 0, s;
	for (i = 0; i < ysize; ++i) {
		s = x->val[i] + y->val[i] + r;
		sum->val[i] = s % 10;
		r = s / 10;
	}

	// Propagate remainder through x
	for (; i < xsize; ++i) {
		s = x->val[i] + r;
		sum->val[i] = s % 10;
		r = s / 10;
	}

	// If remainder != 0, then sum is of size xsize + 1.
	if (r != 0) {
		sum->size = xsize + 1;
		sum->val[xsize] = r;
	}
	// Otherwise, sum is of size xsize. Shrink x->val by 1 byte.
	else {
		sum->val = realloc(sum->val, xsize);	// http://stackoverflow.com/q/7078019
		sum->size = xsize;
	}

	return sum;
}

// Compute x - y. Note: it is assumed that x >= y, which suffices for
// the implementation of RSA. Behavior when x < y is undefined.
BigInt * Subtract(BigInt * x, BigInt * y) {
	int xsize = x->size;
	int ysize = y->size;
	if (xsize < ysize) return NULL;

	BigInt * diff = malloc(sizeof(BigInt));
	diff->val = malloc(xsize * sizeof(unsigned char));

	// Subtract the last ysize digits of y from x
	int i, d, r = 0, diffsize = 0;
	for (i = 0; i < ysize; ++i) {
		d = x->val[i] - y->val[i] + 10 + r;
		if ((diff->val[i] = d % 10))
			diffsize = i;
		r = d / 10 - 1;
	}

	// Propagate through the rest of x
	for (; i < xsize; ++i) {
		d = x->val[i] + 10 + r;
		if ((diff->val[i] = d % 10))
			diffsize = i;
		r = d / 10 - 1;
	}

	diff->size = ++diffsize;
	diff->val = realloc(diff->val, diffsize);
	return diff;
}

// Compute x * y, where y < 10. Used in base case of Karatsuba multiplication.
BigInt * Mult_Digit(BigInt * x, unsigned char y) {
	int xsize = x->size;
	BigInt * prod = malloc(sizeof(BigInt));
	prod->val = malloc((xsize + 1) * sizeof(unsigned char));

	int i, r = 0, p, prodsize = 0;
	for (i = 0; i < xsize; ++i) {
		p = x->val[i] * y + r;
		if ((prod->val[i] = p % 10))
			prodsize = i;
		r = p / 10;
	}

	if (r != 0) {
		prod->val[xsize] = r;
		prod->size = xsize + 1;
	}
	else {
		prod->size = ++prodsize;
		prod->val = realloc(prod->val, prodsize);	// http://stackoverflow.com/q/7078019
	}

	return prod;
}

// Multiply x by 10^M, where M is a nonnegative integer.
BigInt * Mult_10ToM(BigInt * x, unsigned int M) {
	int xsize = x->size;
	BigInt * prod = malloc(sizeof(BigInt));
	prod->size = M + xsize;
	prod->val = malloc(prod->size * sizeof(unsigned char));
	memcpy(prod->val + prod->size - xsize, x->val, xsize);
	memset(prod->val, 0, prod->size - xsize);
	return prod;
}

// Recursively multiply x and y using Karatsuba algorithm.
BigInt * Mult(BigInt * x, BigInt * y) {

	// Base case: either x or y is a single digit
	if (x->size == 1) return Mult_Digit(y, x->val[0]);
	if (y->size == 1) return Mult_Digit(x, y->val[0]);

	// Swap pointers so that xsize >= ysize.
	BigInt * tmp;
	if (x->size < y->size) {
		tmp = y;
		y = x;
		x = tmp;
	}

	// If necessary, copy y to tmp and pad with zeros so xsize = ysize
	int xsize = x->size;
	int ysize = y->size;
	if (ysize < xsize) {
		tmp = malloc(sizeof(BigInt));
		tmp->val = malloc(xsize * sizeof(unsigned char));
		tmp->size = xsize;
		memcpy(tmp->val, y->val, ysize);
		memset(tmp->val + ysize, 0, xsize - ysize);
	}
	else tmp = y;

	// Compute midpoint at which x and y will be split
	int m = xsize / 2;
	int r = xsize % 2;

	// Split digits around midpoint
	BigInt * low_x = malloc(sizeof(BigInt));
	BigInt * high_x = malloc(sizeof(BigInt));
	BigInt * low_y = malloc(sizeof(BigInt));
	BigInt * high_y = malloc(sizeof(BigInt));
	low_x->val = x->val;
	low_x->size = m;
	high_x->val = x->val + m;
	high_x->size = m + r;
	low_y->val = tmp->val;
	high_y->val = tmp->val + m;

	// Ensure that low_y and high_y have no extra 0-padding
	if (m >= ysize) {
		low_y->size = ysize;
		high_y->size = 1;
	}
	else {
		low_y->size = m;
		high_y->size = ysize - m;
	}

	// Compute the coefficients for the base-10^m expansion of x*y
	BigInt * z0 = Mult(low_x, low_y);
	BigInt * z1_op1 = Add(low_x, high_x);
	BigInt * z1_op2 = Add(low_y, high_y);
	BigInt * z1 = Mult(z1_op1, z1_op2);
	BigInt * z2 = Mult(high_x, high_y);

	// Compute product
	BigInt * p0 = Mult_10ToM(z2, 2*m);
	BigInt * p1_op1 = Subtract(z1, z2);
	BigInt * p1_op2 = Subtract(p1_op1, z0);
	BigInt * p1 = Mult_10ToM(p1_op2, m);
	BigInt * prod_op1 = Add(p0, p1);
	BigInt * prod = Add(prod_op1, z0);

	// Free memory
	FreeBigInt(z0);	FreeBigInt(z1);	FreeBigInt(z1_op1); FreeBigInt(z1_op2);
	FreeBigInt(z2);	free(low_x); free(high_x); free(low_y);	free(high_y);
	FreeBigInt(p0);	FreeBigInt(p1);	FreeBigInt(p1_op1); FreeBigInt(p1_op2);
	FreeBigInt(prod_op1);

	return prod;
}

// Compute x (mod n), where n is a positive integer. If n = 0, returns NULL.
BigInt * Mod(BigInt * x, BigInt * n) {
	int xsize = x->size;
	int nsize = n->size;

	// If n is zero, return NULL
	if (nsize == 1 && n->val[0] == 0)
		return NULL;

	// Create copy of x so that input is not modified.
	BigInt * xcpy = malloc(sizeof(BigInt));
	xcpy->val = malloc(xsize * sizeof(unsigned char));
	memcpy(xcpy->val, x->val, xsize);

	// If x < n, then x % y = x
	if (!GTEqual(x, n)) {
		xcpy->size = xsize;
		return xcpy;
	}

	// Perform long division and return remainder r.
	int i, q, offset, n_msb = n->val[nsize - 1];
	BigInt * xptr = malloc(sizeof(BigInt));
	BigInt * prod;
	BigInt * r = NULL;
	for (i = xsize; i >= nsize; ++i) {
		offset = i - nsize;
		xptr->size = nsize;
		xptr->val = xcpy->val + offset;

		// Compute q = xptr / n (integer division) and compute n * q.
		// If q is 0, add digit to xptr so that q > 0.
		if (GTEqual(xptr, n))
			q = xcpy->val[i - 1] / n_msb;
		else {
			if (i == nsize) break;
			else {
				++xptr->size;
				--xptr->val;
				--offset;
				q = (10 * xcpy->val[i - 1] + xcpy->val[i - 2]) / n_msb;
			}
		}
		prod = Mult_Digit(n, q);
		while(!GTEqual(xptr, prod)) {	// Looping here is very inefficient
			FreeBigInt(prod);
			prod = Mult_Digit(n, --q);
		}

		// Compute xptr - nq. The remainder r = xptr % n.
		if (r) FreeBigInt(r);
		r = Subtract(xptr, prod);

		// Write remainder r back to xcpy and adjust i for next loop.
		memcpy(xptr->val, r->val, r->size);
		i = offset + r->size;
		while (xcpy->val[--i] == 0 && i > 0);
	}

	free(r->val);
	r->size = i;
	r->val = malloc(i * sizeof(unsigned char));
	memcpy(r->val, xcpy->val, i);
	FreeBigInt(xcpy);
	free(xptr);
	return r;
}

// Compute x^e (mod n), where n and e are positive integers.
BigInt * ModPow (BigInt * x, BigInt * e, BigInt * n) {
	return NULL;
}
