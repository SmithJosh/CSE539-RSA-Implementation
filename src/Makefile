rsa: rsa.c rsa.h 
	gcc rsa.c -lgmp -lcrypto -o rsa

debug: rsa.c rsa.h
	gcc rsa.c -lgmp -lcrypto -o debug_rsa -g

clean:
	-rm rsa debug_rsa
	-rm -rf *.dSYM

