# uncomment the desired crypto lib line
CRYPTO=mbedtls
#CRYPTO=openssl
#CRYPTO=ipp_crypto

TARGET=crypto_test
CC=gcc

COMMON_LFLAGS=-lstdc++
COMMON_CFLAGS=-I./../

MBEDTLS_CFLAGS=-I./../mbedtls/include/ -D MBEDTLS
MBEDTLS_LFLAGS=-lmbedtls -lmbedcrypto -lmbedx509 -L./../mbedtls/library/

OSSLDIR= /usr/local/openssl
OPENSSL_CFLAGS=-I$(OSSLDIR)/include/ -D OPENSSL -O0 -g
OPENSSL_LFLAGS=-L$(OSSLDIR)/lib64 -lssl -lcrypto -ldl

IPP_CRYPTO_CFLAGS=-D IPP_CRYPTO
IPP_CRYPTO_LFLAGS=

ifeq ($(CRYPTO),mbedtls)
	CFLAGS=$(COMMON_CFLAGS) $(MBEDTLS_CFLAGS)
	LFLAGS=$(COMMON_LFLAGS) $(MBEDTLS_LFLAGS)
else
	ifeq ($(CRYPTO),openssl)
		CFLAGS=$(COMMON_CFLAGS) $(OPENSSL_CFLAGS)
		LFLAGS=$(COMMON_LFLAGS) $(OPENSSL_LFLAGS)
	else
		ifeq ($(CRYPTO),ipp_crypto)
			CFLAGS=$(COMMON_CFLAGS) $(IPP_CRYPTO_CFLAGS)
			LFLAGS=$(COMMON_LFLAGS) $(IPP_CRYPTO_LFLAGS)
		else
			CFLAGS=$(COMMON_CFLAGS)
			LFLAGS=$(COMMON_LFLAGS)
		endif
	endif
endif


DEPS = ../utils.h ../crypto_wrapper.h ../types.h
ifeq ($(CRYPTO),mbedtls)
OBJ = main.o crypto_wrapper_mbedtls.o utils.o types.o
else
	ifeq ($(CRYPTO),openssl)
	OBJ = main.o crypto_wrapper_openssl.o utils.o types.o
	else
	OBJ = main.o crypto_wrapper_empty.o utils.o types.o
	endif
endif

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LFLAGS)

main.o: main.cpp $(DEPS)
	$(CC) -c -o main.o main.cpp $(CFLAGS)
	
utils.o: ../utils.cpp $(DEPS)
	$(CC) -c -mrdrnd -o utils.o ../utils.cpp $(CFLAGS)
	
crypto_wrapper_mbedtls.o: ../crypto_wrapper_mbedtls.cpp $(DEPS)
	$(CC) -c -o crypto_wrapper_mbedtls.o ../crypto_wrapper_mbedtls.cpp $(CFLAGS)

crypto_wrapper_openssl.o: ../crypto_wrapper_openssl.cpp $(DEPS)
	$(CC) -c -o crypto_wrapper_openssl.o ../crypto_wrapper_openssl.cpp $(CFLAGS)
	
crypto_wrapper_empty.o: ../crypto_wrapper_empty.cpp $(DEPS)
	$(CC) -c -o crypto_wrapper_empty.o ../crypto_wrapper_empty.cpp $(CFLAGS)
	
types.o: ../types.cpp $(DEPS)
	$(CC) -c -o types.o ../types.cpp $(CFLAGS)
	
clean :
	rm -f $(TARGET) $(OBJ)

