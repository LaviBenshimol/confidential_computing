#ifndef CRYPTO_H
#define CRYPTO_H


/* types */

#include "types.h"

#ifdef MBEDTLS
#include  "mbedtls/pk.h"
#include "mbedtls/dhm.h"
#define KeypairContext mbedtls_pk_context
#define DhContext mbedtls_dhm_context
#else
#ifdef OPENSSL
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/dh.h>

#define KeypairContext EVP_PKEY_CTX 						 
#define DhContext EVP_PKEY
#else
// dummy default definition to pass build
#define KeypairContext int 						 
#define DhContext int

#endif // #ifdef OPENSSL
#endif // #ifdef MBEDTLS


// ****************************** Constants ****************************************
static constexpr size_t MAX_PASSWORD_SIZE_BYTES		= 64;
static constexpr size_t SYMMETRIC_KEY_SIZE_BYTES	= 1; //???
static constexpr size_t HMAC_SIZE_BYTES				= 1; //???
static constexpr size_t SIGNATURE_SIZE_BYTES		= 1; //???
static constexpr size_t DH_KEY_SIZE_BYTES			= 1; //???


#define IN
#define OUT
#define INOUT


class CryptoWrapper
{
public:

	// *************************** Symmetric **************************************
	static bool hmac_SHA256(IN const BYTE* key, IN size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes);

	static bool deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
		IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
		IN const BYTE* context, IN size_t contextSizeBytes,
		OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes);

	// IV and MAC are packed within the ciphertext
	static size_t getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes);

	// IV and MAC are packed within the ciphertext
	static size_t getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes);
	
	// IV is generated as random
	// IV and MAC are packed within the ciphertext
	static bool encryptAES_GCM256(IN const BYTE* key, size_t keySizeBytes,
		IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
		IN const BYTE* aad, IN size_t aadSizeBytes,
		OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes);

	// expecting IV and MAC to be packed within the ciphertext
	static bool decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
		IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
		IN const BYTE* aad, IN size_t aadSizeBytes,
		OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes);


	// *************************** RSA **************************************
	static bool readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext);

	static bool signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes);

	static bool verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result);

	static void cleanKeyContext(INOUT KeypairContext** pKeyContext);


	// ********************** Diffie–Hellman *******************************
	static bool startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes);

	static bool getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes);

	static void cleanDhContext(INOUT DhContext** pDhContext);


	// ********************** Certificates *******************************
	static bool checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN);

	static bool getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext);

private:

	static bool writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes);

	static bool loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes);
};


#endif // #ifndef CRYPTO_H






