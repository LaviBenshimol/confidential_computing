

#include <stdlib.h>
#include <string.h>
#include "crypto_wrapper.h"
#include "utils.h"
#ifdef MBEDTLS
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/md.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"


#ifdef WIN
#pragma comment (lib, "mbedtls.lib")
#endif // #ifdef WIN



static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
// SHA3 512 bits is 64 Bytes (slide 15)
static constexpr size_t HASH_SIZE_BYTES			= 64;
// Recommanded IV is 96 bits - 12 Bytes (Slide 12)
static constexpr size_t IV_SIZE_BYTES			= 12;
// Output of GMAC is always 128 bits (slide 15)
static constexpr size_t GMAC_SIZE_BYTES			= 16;


int getRandom(void* contextData, BYTE* output, size_t len)
{
	if (!Utils::generateRandom(output, len))
	{
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}
	return (0);
}





/**
 * @brief Computes the HMAC of a given message using SHA-256 or SHA3-512 (if supported and key is long enough).
 *
 * This function calculates a Hash-based Message Authentication Code (HMAC) over the input message
 * using either SHA-256 (default) or SHA3-512 (optional). The selection is based on the key size:
 * if the key is at least 48 bytes and SHA3-512 is supported by the mbedTLS build, it will be used.
 *
 * It uses the mbedTLS message digest APIs to initialize an HMAC context, bind the key,
 * update with the message data, and finalize the digest into the provided output buffer.
 *
 * @param[in]  key                 Pointer to the HMAC key.
 * @param[in]  keySizeBytes       Size of the key in bytes.
 * @param[in]  message            Pointer to the input message buffer.
 * @param[in]  messageSizeBytes   Size of the input message in bytes.
 * @param[out] macBuffer          Pointer to the buffer where the computed HMAC will be written.
 * @param[in]  macBufferSizeBytes Size of the macBuffer in bytes. Must be at least 32 for SHA-256, or 64 for SHA3-512.
 *
 * @return true on success, false on failure (e.g., null pointers, buffer too small, unsupported hash type).
 *
 * @note The function uses SHA-256 by default. If the key is large (>= 48 bytes) and SHA3-512 is compiled in,
 *       it will switch to SHA3-512 automatically.
 *
 * @warning The caller must ensure that macBuffer is securely allocated and cleared if needed,
 *          especially when handling cryptographic outputs.
 */
bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes,
								 IN const BYTE* message, size_t messageSizeBytes,
								 OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{


	if (key == NULL || message == NULL || macBuffer == NULL ||
		keySizeBytes == 0 || messageSizeBytes == 0 || macBufferSizeBytes == 0)
	{
		return false;
	}

	// Choose digest type based on key size (just an example strategy)
	mbedtls_md_type_t hashType = MBEDTLS_MD_SHA256;

#if defined(MBEDTLS_MD_SHA3_512)
	if (keySizeBytes >= 48) // Arbitrary: assume if key is long enough, user wants SHA3-512
	{
		hashType = MBEDTLS_MD_SHA3_512;
	}
#endif

	const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(hashType);
	if (md_info == NULL)
	{
		return false;
	}

	size_t digestSize = mbedtls_md_get_size(md_info);
	if (macBufferSizeBytes < digestSize)
	{
		return false;
	}

	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);

	bool success = false;

	if (mbedtls_md_setup(&ctx, md_info, 1 /* use HMAC */) != 0)
		goto cleanup;

	if (mbedtls_md_hmac_starts(&ctx, key, keySizeBytes) != 0)
		goto cleanup;

	if (mbedtls_md_hmac_update(&ctx, message, messageSizeBytes) != 0)
		goto cleanup;

	if (mbedtls_md_hmac_finish(&ctx, macBuffer) != 0)
		goto cleanup;

	success = true;

	cleanup:
		mbedtls_md_free(&ctx);
	return success;
}



bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
IN const BYTE* context, IN size_t contextSizeBytes,
OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	const mbedtls_md_info_t* mdSHA256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (mdSHA256 == NULL)
	{
		printf("Failed to get SHA256 md_info\n");
		return false;
	}

	int result = mbedtls_hkdf(mdSHA256,
		salt, saltSizeBytes,
		secretMaterial, secretMaterialSizeBytes,
		context, contextSizeBytes,
		outputBuffer, outputBufferSizeBytes);

	if (result != 0)
	{
		printf("mbedtls_hkdf failed with error: %d\n", result);
		return false;
	}

	return true;
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
	BYTE iv[IV_SIZE_BYTES]; // 12-byte IV
	BYTE mac[GMAC_SIZE_BYTES]; // 16-byte MAC tag
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);

    // Sanity check - have either plaintext or AAD
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

	// === Step 1: Generate a random IV ===
	if (!Utils::generateRandom(iv, IV_SIZE_BYTES)) {
		return false;
	}

	// === Step 2: Initialize GCM context ===
	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);

	// Set the AES-256 key (key size is in bits!)
	if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keySizeBytes * 8) != 0) {
		mbedtls_gcm_free(&gcm);
		return false;
	}

	// === Step 3: Perform GCM encryption with MAC (GMAC) ===
	BYTE* ciphertext = ciphertextBuffer + IV_SIZE_BYTES;
	int ret = mbedtls_gcm_crypt_and_tag(
		&gcm,
		MBEDTLS_GCM_ENCRYPT,
		plaintextSizeBytes,
		iv, IV_SIZE_BYTES,
		aad, aadSizeBytes,
		plaintext,
		ciphertext,
		GMAC_SIZE_BYTES,
		mac);

	mbedtls_gcm_free(&gcm);

	if (ret != 0) {
		return false;
	}

	// === Step 4: Copy IV to the beginning of the ciphertext buffer ===
	memcpy(ciphertextBuffer, iv, IV_SIZE_BYTES);

	// === Step 5: Copy MAC tag to the end of the buffer ===
	memcpy(ciphertextBuffer + IV_SIZE_BYTES + plaintextSizeBytes, mac, GMAC_SIZE_BYTES);

	// === Step 6: Return the total size to the caller ===
	if (pCiphertextSizeBytes != NULL) {
		*pCiphertextSizeBytes = ciphertextSizeBytes;
	}

	return true;
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
	KeypairContext* newContext = (KeypairContext*)Utils::allocateBuffer(sizeof(KeypairContext));
	if (newContext == NULL)
	{
		printf("Error during memory allocation in readRSAKeyFromFile()\n");
		return false;
	}

	mbedtls_pk_init(newContext);
	ByteSmartPtr bufferSmartPtr = Utils::readBufferFromFile(keyFilename);
	if (bufferSmartPtr == NULL)
	{
		printf("Error reading keypair file: %s\n", keyFilename);
		return false;
	}

	int res = mbedtls_pk_parse_key(newContext,
								   bufferSmartPtr, bufferSmartPtr.size(),
								   (const BYTE*)filePassword,
								   filePassword ? strnlen_s(filePassword, MAX_PASSWORD_SIZE_BYTES) : 0,
								   NULL, NULL); // ✅ FIXED: don't use getRandom for PEM

	if (res != 0)
	{
		char errBuf[128];
		mbedtls_strerror(res, errBuf, sizeof(errBuf));
		printf("mbedtls_pk_parse_key failed: -0x%04X (%s)\n", -res, errBuf);

		cleanKeyContext(&newContext);
		return false;
	}

	cleanKeyContext(pKeyContext);
	*pKeyContext = newContext;
	return true;
}



// bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
// {
// 	if (signatureBufferSizeBytes != SIGNATURE_SIZE_BYTES)
// 	{
// 		printf("Signature buffer size is wrong!\n");
// 		return false;
// 	}
//
// 	// ...
// 	return false;
// }
/**
 * @brief Signs a message using an RSA private key (any size) with PSS padding and SHA-256.
 *
 * This function computes the SHA-256 hash of the input message, and signs it using the provided
 * RSA private key with RSASSA-PSS padding, as required by modern cryptographic standards.
 * It supports any RSA key size; the signature buffer must be at least as large as the key size in bytes.
 *
 * @param[in]  message                  Pointer to the message to be signed.
 * @param[in]  messageSizeBytes         Size of the message in bytes.
 * @param[in]  privateKeyContext        Pointer to an initialized mbedtls_pk_context containing the RSA private key.
 * @param[out] signatureBuffer          Pointer to the buffer where the resulting signature will be stored.
 * @param[in]  signatureBufferSizeBytes Size of the signature buffer in bytes (must be >= key size).
 *
 * @return true on successful signature generation, false on error.
 *
 * @note This function uses SHA-256 as the message digest and applies RSASSA-PSS padding.
 *       The caller is responsible for zeroizing the signature buffer after use.
 */
bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes,
										  IN KeypairContext* privateKeyContext,
										  OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	if (message == NULL || privateKeyContext == NULL || signatureBuffer == NULL)
		return false;

	if (!mbedtls_pk_can_do(privateKeyContext, MBEDTLS_PK_RSA))
		return false;

	size_t key_len = mbedtls_pk_get_len(privateKeyContext); // in bytes
	if (signatureBufferSizeBytes < key_len)
		return false;

	int ret = 0;
	mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
	BYTE hash[32];
	size_t sig_len = 0;  // Moved up to avoid goto jump over init

	// Compute SHA256 hash of the message
	ret = mbedtls_md(mbedtls_md_info_from_type(md_type), message, messageSizeBytes, hash);
	if (ret != 0)
		return false;

	// Setup RNG
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
		goto cleanup;

	// Sign the hash using RSASSA-PSS
	ret = mbedtls_pk_sign(privateKeyContext, md_type,
						  hash, 0,                          // hash and hash_len=0 for raw
						  signatureBuffer, signatureBufferSizeBytes,
						  &sig_len,
						  mbedtls_ctr_drbg_random, &ctr_drbg);

	if (ret != 0 || sig_len > signatureBufferSizeBytes)
		goto cleanup;

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return true;

	cleanup:
		mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return false;
}


// bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
// {
// 	if (signatureSizeBytes != SIGNATURE_SIZE_BYTES)
// 	{
// 		printf("Signature size is wrong!\n");
// 		return false;
// 	}
//
// 	// ...
// 	return false;
// }
/**
 * @brief Verifies a message signature using an RSA public key (any size) with PSS padding and SHA-256.
 *
 * This function computes the SHA-256 hash of the message and verifies the provided signature
 * using the given RSA public key and RSASSA-PSS padding scheme. Supports any RSA key size.
 *
 * @param[in]  message                Pointer to the message whose signature is to be verified.
 * @param[in]  messageSizeBytes       Size of the message in bytes.
 * @param[in]  publicKeyContext       Pointer to an initialized mbedtls_pk_context containing the RSA public key.
 * @param[in]  signature              Pointer to the signature to be verified.
 * @param[in]  signatureSizeBytes     Size of the signature buffer in bytes.
 * @param[out] result                 Pointer to boolean; set to true if signature is valid, false otherwise.
 *
 * @return true if verification was performed (regardless of outcome), false if an internal error occurred.
 *
 * @note This function uses SHA-256 as the message digest and assumes PSS padding.
 */
bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes,
                                            IN KeypairContext* publicKeyContext,
                                            IN const BYTE* signature, IN size_t signatureSizeBytes,
                                            OUT bool* result)
{
    if (message == NULL || publicKeyContext == NULL || signature == NULL || result == NULL)
        return false;

    *result = false;

    if (!mbedtls_pk_can_do(publicKeyContext, MBEDTLS_PK_RSA))
        return false;

    size_t key_len = mbedtls_pk_get_len(publicKeyContext); // in bytes
    if (signatureSizeBytes != key_len)
        return true; // Valid call, but signature is not the correct size, so result = false

    int ret = 0;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    BYTE hash[32];

    ret = mbedtls_md(mbedtls_md_info_from_type(md_type), message, messageSizeBytes, hash);
    if (ret != 0)
        return false;

    ret = mbedtls_pk_verify(publicKeyContext, md_type, hash, 0, signature, signatureSizeBytes);
    if (ret == 0)
        *result = true;

    return true;
}


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		mbedtls_pk_free(*pKeyContext);
		Utils::freeBuffer(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN mbedtls_pk_context* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	memset(publicKeyPemBuffer, 0, publicKeyBufferSizeBytes);
	if (mbedtls_pk_write_pubkey_pem(keyContext, publicKeyPemBuffer, publicKeyBufferSizeBytes) != 0)
	{
		printf("Error during mbedtls_pk_write_pubkey_pem()\n");
		return false;
	}

	return true;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	mbedtls_pk_init(context);
	if (mbedtls_pk_parse_public_key(context, publicKeyPemBuffer, strnlen_s((const char*)publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES) + 1) != 0)
	{
		printf("Error during mbedtls_pk_parse_key() in loadPublicKeyFromPemBuffer()\n");
		return false;
	}
	return true;
}


bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	DhContext* dhContext = (DhContext*)Utils::allocateBuffer(sizeof(DhContext));
	if (dhContext == NULL)
	{
		printf("Error during memory allocation in startDh()\n");
		return false;
	}
	mbedtls_dhm_init(dhContext);

	mbedtls_mpi P;
	mbedtls_mpi G;
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&G);

	const BYTE pBin[] = MBEDTLS_DHM_RFC3526_MODP_3072_P_BIN;
	const BYTE gBin[] = MBEDTLS_DHM_RFC3526_MODP_3072_G_BIN;

	// select the finite group modulus
	mbedtls_mpi_read_binary(&P, pBin, sizeof(pBin));

	// select the pre-agreed generator element of the finite group
	mbedtls_mpi_read_binary(&G, gBin, sizeof(gBin));


	// ...

	cleanDhContext(&dhContext);
	return false;
}


bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{
	// ...
	return false;
}


void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		mbedtls_dhm_free(*pDhContext);
		Utils::freeBuffer(*pDhContext);
		*pDhContext = NULL;
	}
}


bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt clicert;
	mbedtls_x509_crt_init(&cacert);
	mbedtls_x509_crt_init(&clicert);
	uint32_t flags;
	int res = -1;

	if (mbedtls_x509_crt_parse(&cacert, cACcertBuffer, cACertSizeBytes) != 0)
	{
		printf("Error parsing CA certificate\n");
		return false;
	}

	if (mbedtls_x509_crt_parse(&clicert, certBuffer, certSizeBytes) != 0)
	{
		printf("Error parsing certificate to verify\n");
		mbedtls_x509_crt_free(&cacert);
		return false;
	}

	// ...

	mbedtls_x509_crt_free(&cacert);
	mbedtls_x509_crt_free(&clicert);
	return (res == 0);
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{
	BYTE publicKeyPemBuffer[PEM_BUFFER_SIZE_BYTES];

	mbedtls_x509_crt clicert;
	mbedtls_x509_crt_init(&clicert);

	if (mbedtls_x509_crt_parse(&clicert, certBuffer, certSizeBytes) != 0)
	{
		printf("Error parsing certificate to read\n");
		mbedtls_x509_crt_free(&clicert);
		return false;
	}
	
	KeypairContext* certPublicKeyContext = &(clicert.pk);
	// we will use a PEM buffer to create an independant copy of the public key context
	bool result = writePublicKeyToPemBuffer(certPublicKeyContext, publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES);
	mbedtls_x509_crt_free(&clicert);

	if (result)
	{
		KeypairContext* publicKeyContext = (KeypairContext*)Utils::allocateBuffer(sizeof(KeypairContext));
		if (publicKeyContext == NULL)
		{
			printf("Error during memory allocation in getPublicKeyFromCertificate()\n");
			return false;
		}

		if (loadPublicKeyFromPemBuffer(publicKeyContext, publicKeyPemBuffer, PEM_BUFFER_SIZE_BYTES))
		{
			cleanKeyContext(pPublicKeyContext);
			*pPublicKeyContext = publicKeyContext;
			return true;
		}
		else
		{
			cleanKeyContext(&publicKeyContext);
			return false;
		}
	}
	return false;
}

#endif // #ifdef MBEDTLS


/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://tls.mbed.org/api/gcm_8h.html
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* mbedtls_md_hmac
* mbedtls_hkdf
* mbedtls_gcm_setkey
* mbedtls_gcm_crypt_and_tag
* mbedtls_gcm_auth_decrypt
* mbedtls_md
* mbedtls_pk_get_type
* mbedtls_pk_rsa
* mbedtls_rsa_set_padding
* mbedtls_rsa_rsassa_pss_sign
* mbedtls_md_info_from_type
* mbedtls_rsa_rsassa_pss_verify
* mbedtls_dhm_set_group
* mbedtls_dhm_make_public
* mbedtls_dhm_read_public
* mbedtls_dhm_calc_secret
* mbedtls_x509_crt_verify
* 
* 
* 
* 
* 
* 
* 
*/