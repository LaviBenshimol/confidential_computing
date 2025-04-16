#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
static constexpr size_t HASH_SIZE_BYTES			= 0; //To be define by the participants
static constexpr size_t IV_SIZE_BYTES			= 0; //To be define by the participants
static constexpr size_t GMAC_SIZE_BYTES			= 0; //To be define by the participants



bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	EVP_MD_CTX* ctx = NULL;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		goto err;
	}


err:
	EVP_MD_CTX_free(ctx);

	return false;

	// ...
}


bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if(pctx == NULL)
	{
		printf("failed to get HKDF context\n");
		goto err;	
	}

	// ...	
err:
	EVP_PKEY_CTX_free(pctx);

	return ret;


}


size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);
	
	if ((plaintext == NULL || plaintextSizeBytes == 0) && (aad == NULL || aadSizeBytes == 0))
	{
		return false;
	}

	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes == 0)
	{
		if (pCiphertextSizeBytes != NULL)
		{
			*pCiphertextSizeBytes = ciphertextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (ciphertextBufferSizeBytes < ciphertextSizeBytes)
	{
		return false;
	}

	// ...
	return false;
}

bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);
	
	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}
	
	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		return false;
	}

	// ...
	

	if (pPlaintextSizeBytes != NULL)
	{
		*pPlaintextSizeBytes = plaintextSizeBytes;
	}
	return false;
}

bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	return false;
}


bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	return false;
}


bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{

	return false;
}


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}

bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	unsigned char generator = 2;
	

	p = BN_get_rfc3526_prime_3072(NULL);
	if (p == NULL)
	{
		goto err;
	}

	g = BN_bin2bn(&generator, 1, NULL);
	if (g == NULL)
	{
		goto err;
	}

	// ...	

err:
	BN_free(p);
	BN_free(g);

	return ret;


}

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{

	// ...
	return false;

}



bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{

	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* derivationCtx = NULL;

	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
	{
		goto err;
	}

	CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey);

	// ...

err:
	return ret;
}


void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	int ret = 0;
	X509* userCert = NULL;
	X509* caCert = NULL;


	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

// ...

err:
	X509_free(caCert);
	X509_free(userCert);

	return ret;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{

	return false;
}

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/
