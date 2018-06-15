CC=gcc
CFLAGS= -W -fPIC

cauth:
	$(CC) $(CFLAGS) -c pam/src/cauth.c
	ld -x --shared -o cauth.so cauth.o -lssl -lcrypto
	mv cauth.so /lib64/security/.
	rm cauth.o

