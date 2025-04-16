# uncomment the desired crypto lib line
#CRYPTO=mbedtls
#CRYPTO=openssl
#CRYPTO=ipp_crypto

TARGET=udp_party
CC=gcc

COMMON_LFLAGS=-lstdc++
COMMON_CFLAGS=-I./../

MBEDTLS_CFLAGS=-I./mbedtls/include/ -D MBEDTLS
MBEDTLS_LFLAGS=-lmbedtls -lmbedcrypto -lmbedx509 -L./mbedtls/library/


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

ifeq ($(CRYPTO),mbedtls)
	DEPS = session.h sockets.h client.h server.h client_session.h server_session.h utils.h crypto_wrapper.h types.h eliza.h
	OBJ = main.o session.o client_session.o server_session.o sockets.o client.o server.o utils.o crypto_wrapper_mbedtls.o types.o eliza.o
else
	ifeq ($(CRYPTO),openssl)
			DEPS = session.h sockets.h client.h server.h client_session.h server_session.h utils.h crypto_wrapper.h types.h eliza.h
			OBJ = main.o session.o client_session.o server_session.o sockets.o client.o server.o utils.o crypto_wrapper_openssl.o types.o eliza.o
	else
			DEPS = session.h sockets.h client.h server.h client_session.h server_session.h utils.h crypto_wrapper.h types.h eliza.h
			OBJ = main.o session.o client_session.o server_session.o sockets.o client.o server.o utils.o crypto_wrapper_empty.o types.o eliza.o
	endif	
endif

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LFLAGS)
	
utils.o: utils.cpp $(DEPS)
	$(CC) -c -mrdrnd -o utils.o utils.cpp $(CFLAGS)
	
%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
clean :
	rm -f $(TARGET) $(OBJ)

