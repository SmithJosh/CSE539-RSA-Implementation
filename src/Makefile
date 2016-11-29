test: rsa.c rsa.h test.c
	gcc test.c rsa.c -lgmp -lcrypto -o test -g

rsa: rsa.c rsa.h 
	gcc rsa.c -lgmp -lcrypto -o rsa

debug: rsa.c rsa.h
	gcc rsa.c -lgmp -lcrypto -o debug_rsa -g

clean:
	-rm rsa debug_rsa test
	-rm -rf *.dSYM

