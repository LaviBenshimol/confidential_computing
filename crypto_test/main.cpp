#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"


static constexpr size_t MESSAGE_BUFFER_SIZE_BYTES = 1000;


bool deriveKeyFromRandom(BYTE* secretKeyBuffer, size_t secretKeyBufferSize, const BYTE* context, size_t contextSize)
{
	size_t initialSecretSize = secretKeyBufferSize;
	BYTE* initialSecret = (BYTE*)malloc(initialSecretSize);
	if (initialSecret == NULL)
	{
		printf("Error allocating memory!\n");
		return false;
	}

	if (!Utils::generateRandom(initialSecret, secretKeyBufferSize))
	{
		printf("Error generating initialSecret!\n");
		free(initialSecret);
		return false;
	}

	BYTE salt[32];
	if (!Utils::generateRandom(salt, 32))
	{
		printf("Error generating salt!\n");
		free(initialSecret);
		return false;
	}
	
	if (!CryptoWrapper::deriveKey_HKDF_SHA256(salt, 32, initialSecret, initialSecretSize, context, contextSize, secretKeyBuffer, secretKeyBufferSize))
	{
		printf("Error generating key!\n");
		free(initialSecret);
		return false;
	}

	free(initialSecret);
	return true;
}


bool testHMAC()
{
	// test vector from - https://datatracker.ietf.org/doc/html/rfc4231
	BYTE secretKey[131];
	for (unsigned int i = 0; i < sizeof(secretKey); i++)
	{
		secretKey[i] = 0xaa;
	}
	
	const BYTE messageBuffer[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x2d, 0x20, 0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x46, 0x69, 0x72, 0x73, 0x74 };
	BYTE resultMacBuffer[HMAC_SIZE_BYTES];
	const BYTE referenceMac[] = { 0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54 };

	bool result = CryptoWrapper::hmac_SHA256(secretKey, sizeof(secretKey), messageBuffer, sizeof(messageBuffer), resultMacBuffer, HMAC_SIZE_BYTES);
	Utils::secureCleanMemory(secretKey, sizeof(secretKey));
	
	if (result)
		return memcmp(resultMacBuffer, referenceMac, HMAC_SIZE_BYTES) == 0;
	else
		return false;
}


bool testSymmetricEncryption()
{
	BYTE secretKey[SYMMETRIC_KEY_SIZE_BYTES];	// We must use the size recommended by Intel crypto guidelines
	char ciphertextBuffer[MESSAGE_BUFFER_SIZE_BYTES];	// For AES-GCM the ciphertext is the same size as the plaintext
	char plaintextBuffer[MESSAGE_BUFFER_SIZE_BYTES];	// For AES-GCM the ciphertext is the same size as the plaintext

	const char* keyContext = "testing symmetric key encryption";
	const char* originalPlaintext = "This is a secret plaintext that we want to protect";
	size_t plaintextSize = strnlen_s(originalPlaintext, MESSAGE_BUFFER_SIZE_BYTES) + 1;
		
	// generate a random key
	// *********************
	if (!deriveKeyFromRandom(secretKey, SYMMETRIC_KEY_SIZE_BYTES, (const BYTE*)keyContext, strnlen_s(keyContext, 1000)))
	{
		printf("Error during deriveKeyFromRandom!\n");
		return false;
	}

	// do encryption of the plaintext
	// ******************************
	size_t ciphertextSize = 0;
	
	if (!CryptoWrapper::encryptAES_GCM256(secretKey, SYMMETRIC_KEY_SIZE_BYTES,	// key
		(const BYTE*)originalPlaintext, plaintextSize,							// plaintext
		(const BYTE*)(&plaintextSize), sizeof(plaintextSize),					// aad
		(BYTE*)ciphertextBuffer, MESSAGE_BUFFER_SIZE_BYTES, &ciphertextSize))	// ciphertext buffer - output
	{
		printf("Error during encryptAES_GCM256!\n");
		Utils::secureCleanMemory(secretKey, SYMMETRIC_KEY_SIZE_BYTES);
		return false;
	}

	// do decryption of the ciphertext and MAC
	// ***************************************
	size_t newPlaintextSize = CryptoWrapper::getPlaintextSizeAES_GCM256(ciphertextSize);

	if (!CryptoWrapper::decryptAES_GCM256(secretKey, SYMMETRIC_KEY_SIZE_BYTES,	// key
		(BYTE*)ciphertextBuffer, ciphertextSize,								// ciphertext
		(const BYTE*)(&newPlaintextSize), sizeof(newPlaintextSize),				// aad - must use the same AAD
		(BYTE*)plaintextBuffer, MESSAGE_BUFFER_SIZE_BYTES, NULL))						// plaintextBuffer - output
	{
		printf("Error during decryptAES_GCM256!\n");
		Utils::secureCleanMemory(secretKey, SYMMETRIC_KEY_SIZE_BYTES);
		return false;
	}


	// check if we got back the original plaintext
	// *******************************************
	if (newPlaintextSize != plaintextSize || strncmp(originalPlaintext, plaintextBuffer, plaintextSize) != 0)
	{
		printf("The calculated plaintext after decryptAES_GCM256 does not match the original!\n");
		Utils::secureCleanMemory(secretKey, SYMMETRIC_KEY_SIZE_BYTES);
		return false;
	}
	
	printf("The plaintext is the same - %s\n", plaintextBuffer);
	Utils::secureCleanMemory(secretKey, SYMMETRIC_KEY_SIZE_BYTES);
	return true;
}


bool readRsaKeypair(const char* keypairFilename, const char* password, const char* certFilename, KeypairContext** pPrivateKeyContext, KeypairContext** pPublicKeyContext)
{
	// read the private key from private key file
	if (!CryptoWrapper::readRSAKeyFromFile(keypairFilename, password, pPrivateKeyContext))
		return false;

	// read the certificate containing the public key
	ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(certFilename);
	if (certBufferSmartPtr == NULL)
	{
		printf("Error reading certificate file\n");
		CryptoWrapper::cleanKeyContext(pPrivateKeyContext);
		return false;
	}

	// read the public key from the buffer containing the certificate
	bool result = CryptoWrapper::getPublicKeyFromCertificate(certBufferSmartPtr, certBufferSmartPtr.size(), pPublicKeyContext);
	return result;
}


bool testRsaSigning(KeypairContext* privateKeyContext, KeypairContext* publicKeyContext, bool toModifyMessage)
{
	char message[] = "This is a message we want to sign for signature verification";
	size_t messageSize = strnlen_s(message, MESSAGE_BUFFER_SIZE_BYTES) + 1;
	BYTE signature[SIGNATURE_SIZE_BYTES];

	if (!CryptoWrapper::signMessageRsa3072Pss((const BYTE*)message, messageSize, privateKeyContext, signature, SIGNATURE_SIZE_BYTES))
		return false;

	if (toModifyMessage)
		message[0] = 't';
	
	bool signatureIsOK = false;
	if (!CryptoWrapper::verifyMessageRsa3072Pss((const BYTE*)message, messageSize, publicKeyContext, signature, SIGNATURE_SIZE_BYTES, &signatureIsOK))
		return false;

	return signatureIsOK;
}


bool testRsa(bool toModifyMessage, const char* keypairFilename, const char* password, const char* certFilename)
{
	KeypairContext* privateKeyContext = NULL;
	KeypairContext* publicKeyContext = NULL;
	
	if (!readRsaKeypair(keypairFilename, password, certFilename, &privateKeyContext, &publicKeyContext))
	{
		printf("readRsaKeypair FAILED!\n");
		return false;
	}
	
	bool result = testRsaSigning(privateKeyContext, publicKeyContext, toModifyMessage);
	CryptoWrapper::cleanKeyContext(&privateKeyContext);
	CryptoWrapper::cleanKeyContext(&publicKeyContext);
	return result;
}


bool testDh()
{
	bool ok = true;
	
	DhContext* dhAliceContext = NULL;
	BYTE alicePublicKeyBuffer[DH_KEY_SIZE_BYTES];
	BYTE aliceSharedSecretBuffer[DH_KEY_SIZE_BYTES];

	DhContext* dhBobContext = NULL;
	BYTE bobSharedSecretBuffer[DH_KEY_SIZE_BYTES];
	BYTE bobPublicKeyBuffer[DH_KEY_SIZE_BYTES];
	

	if (ok && !CryptoWrapper::startDh(&dhAliceContext, alicePublicKeyBuffer, DH_KEY_SIZE_BYTES))
		ok = false;
	
	if (!CryptoWrapper::CryptoWrapper::startDh(&dhBobContext, bobPublicKeyBuffer, DH_KEY_SIZE_BYTES))
		ok = false;

	if (!CryptoWrapper::getDhSharedSecret(dhAliceContext, bobPublicKeyBuffer, DH_KEY_SIZE_BYTES, aliceSharedSecretBuffer, DH_KEY_SIZE_BYTES))
		ok = false;

	if (!CryptoWrapper::getDhSharedSecret(dhBobContext, alicePublicKeyBuffer, DH_KEY_SIZE_BYTES, bobSharedSecretBuffer, DH_KEY_SIZE_BYTES))
		ok = false;

	if (memcmp(aliceSharedSecretBuffer, bobSharedSecretBuffer, DH_KEY_SIZE_BYTES) != 0)
	{
		printf("DH - Shared secret is not the same\n");
		ok = false;
	}

	CryptoWrapper::cleanDhContext(&dhAliceContext);
	CryptoWrapper::cleanDhContext(&dhBobContext);
	return ok;
}


bool testCertificateChecking(const char* certFilename, const char* caCertFilename, const char* expectedCN)
{
	ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(certFilename);
	if (certBufferSmartPtr == NULL)
	{
		printf("Error reading certificate filename - %s\n", certFilename);
		return false;
	}

	ByteSmartPtr cAcertBufferSmartPtr = Utils::readBufferFromFile(caCertFilename);
	if (cAcertBufferSmartPtr == NULL)
	{
		printf("Error reading certificate filename - %s\n", caCertFilename);
		return false;
	}

	bool result = CryptoWrapper::checkCertificate(cAcertBufferSmartPtr, cAcertBufferSmartPtr.size(), certBufferSmartPtr, certBufferSmartPtr.size() , expectedCN);
	return result;
}


static constexpr const char* RSA_KEY_FILENAME = "bob.key";
static constexpr const char* RSA_KEY_PASSWORD = "bobkey";
static constexpr const char* CERTIFICATE_FILENAME = "bob.crt";
static constexpr const char* ROOTCA_CERTIFICATE_FILENAME = "rootCA.crt";
static constexpr const char* EXPECTED_CN = "Bob.com";
static constexpr const char* NON_EXPECTED_CN = "Boby.com";


int main(int argc, char** argv)
{
	if (testHMAC())
		printf("testHMAC PASSED!\n");
	else
		printf("testHMAC FAILED!\n");

	if (testSymmetricEncryption())
		printf("testSymmetricEncryption PASSED!\n");
	else
		printf("testSymmetricEncryption FAILED!\n");

	printf("Testing RSA with key file \"%s\" with passord \"%s\" and public certificate \"%s\"\n", RSA_KEY_FILENAME, RSA_KEY_PASSWORD, CERTIFICATE_FILENAME);
	if (testRsa(false /* do not change message in transit*/, RSA_KEY_FILENAME, RSA_KEY_PASSWORD, CERTIFICATE_FILENAME) && 
		!testRsa(true /* change message in transit*/, RSA_KEY_FILENAME, RSA_KEY_PASSWORD, CERTIFICATE_FILENAME))
		printf("testRsaSigning PASSED!\n");
	else
		printf("testRsaSigning FAILED!\n");

	if (testDh())
		printf("testDh PASSED!\n");
	else
		printf("testDh FAILED!\n");

	printf("Testing cerificate \"%s\" with rooCA certificate \"%s\" for common name \"%s\"\n", CERTIFICATE_FILENAME, ROOTCA_CERTIFICATE_FILENAME, EXPECTED_CN);
	if (testCertificateChecking(CERTIFICATE_FILENAME, ROOTCA_CERTIFICATE_FILENAME, EXPECTED_CN) && !testCertificateChecking(CERTIFICATE_FILENAME, ROOTCA_CERTIFICATE_FILENAME, NON_EXPECTED_CN) )
		printf("testCertificateChecking PASSED!\n");
	else
		printf("testCertificateChecking FAILED!\n");

	return 0;
}