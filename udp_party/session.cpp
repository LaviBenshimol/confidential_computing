#include <list>
#include <stdio.h>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include "session.h"
#include "utils.h"
#include "crypto_wrapper.h"


#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


static constexpr size_t MAX_CONTEXT_SIZE = 100;


Session::Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    _state = UNINITIALIZED_SESSION_STATE;

    _localSocket = new Socket(0);
    if (!_localSocket->valid())
    {
        return;
    }
    _pReferenceCounter = new ReferenceCounter();
    _pReferenceCounter->AddRef();

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = keyFilename;
    _privateKeyPassword = password;
    _localCertFilename = certFilename;
    _rootCaCertFilename = rootCaFilename;
    _expectedRemoteIdentityString = peerIdentity;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


Session::Session(const Session& other)
{
    _state = UNINITIALIZED_SESSION_STATE;
    _pReferenceCounter = other._pReferenceCounter;
    _pReferenceCounter->AddRef();

    _localSocket = other._localSocket;

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = other._privateKeyFilename;
    _privateKeyPassword = other._privateKeyPassword;
    _localCertFilename = other._localCertFilename;
    _rootCaCertFilename = other._rootCaCertFilename;
    _expectedRemoteIdentityString = other._expectedRemoteIdentityString;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


void Session::closeSession()
{
    if (active())
    {
        ByteSmartPtr encryptedMessage = prepareEncryptedMessage(GOODBYE_SESSION_MESSAGE, NULL, 0);
        if (encryptedMessage != NULL)
        {
            sendMessageInternal(GOODBYE_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
            _state = GOODBYE_SESSION_MESSAGE;
        }
    }
}

void Session::destroySession()
{
    cleanDhData();
    if (_pReferenceCounter != NULL && _pReferenceCounter->Release() == 0)
    {
        delete _localSocket;
        _localSocket = NULL;
        delete _pReferenceCounter;
        _pReferenceCounter = NULL;

        if (_privateKeyPassword != NULL)
        {
            // Securely clean the password using Utils function
            Utils::secureCleanMemory((BYTE*)_privateKeyPassword, strnlen_s(_privateKeyPassword, MAX_PASSWORD_SIZE_BYTES));
        }
    }
    else
    {
        _pReferenceCounter = NULL;
    }

    _state = DEACTIVATED_SESSION_STATE;
}

bool Session::active()
{
    return (_state == INITIALIZED_SESSION_STATE ||
        (_state >= FIRST_SESSION_MESSAGE_TYPE && _state <= LAST_SESSION_MESSAGE_TYPE));
}


void Session::setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort) 
{
        memset(&(_remoteAddress), 0, sizeof(sockaddr_in));
        _remoteAddress.sin_family = AF_INET;
        _remoteAddress.sin_port = htons(remotePort);
        _remoteAddress.sin_addr.s_addr = inet_addr(remoteIpAddress);
}


void Session::prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize)
{
    header->sessionId = _sessionId;
    header->messageType = type;
    header->messageCounter =_outgoingMessageCounter;
    header->payloadSize = (unsigned int)messageSize;
}


bool Session::sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize)
{
    if (!active())
    {
        return false;
    }

    MessageHeader header;
    prepareMessageHeader(&header, type, messageSize);

    ByteSmartPtr messageBufferSmartPtr = concat(2, &header, sizeof(header), message, messageSize);
    if (messageBufferSmartPtr == NULL)
    {
        return false;
    }

    bool result = _localSocket->send(messageBufferSmartPtr, messageBufferSmartPtr.size(), &(_remoteAddress));
    if (result)
    {
        _outgoingMessageCounter++;
    }

    return result;
}

void Session::cleanDhData()
{
    // Clean up DH context if it exists
    CryptoWrapper::cleanDhContext(&_dhContext);

    // Zero out sensitive key material
    Utils::secureCleanMemory(_localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    Utils::secureCleanMemory(_remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    Utils::secureCleanMemory(_sharedDhSecretBuffer, DH_KEY_SIZE_BYTES);
}

void Session::deriveMacKey(BYTE* macKeyBuffer)
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "MAC over certificate key %d", _sessionId) <= 0)
    {
        exit(0);
    }

    // Generate random salt for HKDF
    BYTE salt[HMAC_SIZE_BYTES];
    if (!Utils::generateRandom(salt, HMAC_SIZE_BYTES))
    {
        printf("Error generating random salt for MAC key derivation\n");
        exit(0);
    }

    // Derive the MAC key using HKDF with the DH shared secret
    if (!CryptoWrapper::deriveKey_HKDF_SHA256(
            salt, HMAC_SIZE_BYTES,
            _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES,
            (const BYTE*)keyDerivationContext, strnlen_s(keyDerivationContext, MAX_CONTEXT_SIZE),
            macKeyBuffer, HMAC_SIZE_BYTES))
    {
        printf("Error during MAC key derivation\n");
        exit(0);
    }
}


void Session::deriveSessionKey()
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "ENC session key %d", _sessionId) <= 0)
    {
        exit(0);
    }
    
    // Generate random salt for HKDF
    BYTE salt[HMAC_SIZE_BYTES];
    if (!Utils::generateRandom(salt, HMAC_SIZE_BYTES))
    {
        printf("Error generating random salt for session key derivation\n");
        exit(0);
    }

    // Derive the session key using HKDF with the DH shared secret
    if (!CryptoWrapper::deriveKey_HKDF_SHA256(
            salt, HMAC_SIZE_BYTES,
            _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES,
            (const BYTE*)keyDerivationContext, strnlen_s(keyDerivationContext, MAX_CONTEXT_SIZE),
            _sessionKey, SYMMETRIC_KEY_SIZE_BYTES))
    {
        printf("Error during session key derivation\n");
        exit(0);
    }
}


ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    // For message 2 (server), initialize DH and get our public key
    if (messageType == 2)
    {
        // Initialize DH and get our public key
        if (!CryptoWrapper::startDh(&_dhContext, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("prepareSigmaMessage - Failed to initialize DH key exchange\n");
            return NULL;
        }
    }

    // Get my certificate
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        printf("prepareSigmaMessage - Error reading certificate filename - %s\n", _localCertFilename);
        return NULL;
    }

    // Get my private key for signing
    KeypairContext* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        printf("prepareSigmaMessage #%d - Error during readRSAKeyFromFile - %s\n", messageType, _privateKeyFilename);
        cleanDhData();
        return NULL;
    }

    // Concatenate public keys in proper order based on message type
    ByteSmartPtr concatenatedPublicKeysSmartPtr;
    if (messageType == 2)
    {
        // Server: order is client DH key | server DH key
        concatenatedPublicKeysSmartPtr = concat(2, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                              _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }
    else // messageType == 3
    {
        // Client: order is client DH key | server DH key
        concatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                              _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }

    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("prepareSigmaMessage #%d failed - Error concatenating public keys\n", messageType);
        CryptoWrapper::cleanKeyContext(&privateKeyContext);
        return NULL;
    }

    // Sign the concatenated public keys with our private key
    BYTE signature[SIGNATURE_SIZE_BYTES];
    if (!CryptoWrapper::signMessageRsa3072Pss(
            concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(),
            privateKeyContext, signature, SIGNATURE_SIZE_BYTES))
    {
        printf("prepareSigmaMessage #%d failed - Error signing concatenated public keys\n", messageType);
        CryptoWrapper::cleanKeyContext(&privateKeyContext);
        return NULL;
    }

    // Clean up the private key context - we don't need it anymore
    CryptoWrapper::cleanKeyContext(&privateKeyContext);

    // For message 2 (server), calculate shared secret
    if (messageType == 2)
    {
        // Calculate shared secret based on received client public key
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                             _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("prepareSigmaMessage #%d failed - Error calculating shared secret\n", messageType);
            return NULL;
        }
    }

    // Now calculate the MAC over my certificate
    BYTE macKey[HMAC_SIZE_BYTES];
    deriveMacKey(macKey);

    BYTE calculatedMac[HMAC_SIZE_BYTES];
    if (!CryptoWrapper::hmac_SHA256(macKey, HMAC_SIZE_BYTES,
                                   certBufferSmartPtr, certBufferSmartPtr.size(),
                                   calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("prepareSigmaMessage #%d failed - Error calculating MAC\n", messageType);
        Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);
        return NULL;
    }

    // Securely clean the MAC key as we don't need it anymore
    Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);

    // Pack all of the parts together
    ByteSmartPtr messageToSend = packMessageParts(4,
                                               _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                               (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(),
                                               signature, SIGNATURE_SIZE_BYTES,
                                               calculatedMac, HMAC_SIZE_BYTES);

    return messageToSend;
}
// ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
// {
//     if (messageType != 2 && messageType != 3)
//     {
//         return 0;
//     }
//
//     // we will be building the following message parts:
//     // 1: my DH public key
//     // 2: My certificate (PEM)
//     // 3: Signature over concatenated public keys with my permanenet private key
//     // 4: MAC over my certificate with the shared MAC key
//
//     // get my certificate
//     ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
//     if (certBufferSmartPtr == NULL)
//     {
//         printf("prepareDhMessage - Error reading certificate filename - %s\n", _localCertFilename);
//         return NULL;
//     }
//
//     // get my private key for signing
//     KeypairContext* privateKeyContext = NULL;
//     if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
//     {
//         printf("prepareDhMessage #%d - Error during readRSAKeyFromFile - %s\n", messageType, _privateKeyFilename);
//         cleanDhData();
//         return NULL;
//     }
//
//     ByteSmartPtr conacatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
//     if (conacatenatedPublicKeysSmartPtr == NULL)
//     {
//         printf("prepareDhMessage #%d failed - Error concatenating public keys\n", messageType);
//         cleanDhData();
//         return NULL;
//     }
//     BYTE signature[SIGNATURE_SIZE_BYTES];
//     // ...
//
//     // Now we will calculate the MAC over my certiicate
//     BYTE calculatedMac[HMAC_SIZE_BYTES];
//     // ...
//
//     // pack all of the parts together
//     ByteSmartPtr messageToSend = packMessageParts(4, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), signature, SIGNATURE_SIZE_BYTES, calculatedMac, HMAC_SIZE_BYTES);
//     Utils::secureCleanMemory(calculatedMac, HMAC_SIZE_BYTES);
//     return messageToSend;
// }

bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    if (messageType != 2 && messageType != 3)
    {
        return false;
    }

    const unsigned int expectedNumberOfParts = 4;

    // Unpack the received message parts
    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        printf("verifySigmaMessage #%d failed - number of message parts is wrong\n", messageType);
        return false;
    }

    // Extract and validate parts
    // 1. Remote DH public key
    if (parts[0].partSize != DH_KEY_SIZE_BYTES)
    {
        printf("verifySigmaMessage #%d failed - DH key size is wrong\n", messageType);
        return false;
    }

    // Store remote DH public key
    memcpy(_remoteDhPublicKeyBuffer, parts[0].part, DH_KEY_SIZE_BYTES);

    // 2. Remote certificate
    ByteSmartPtr remoteCertBuffer((BYTE*)Utils::allocateBuffer(parts[1].partSize), parts[1].partSize);
    if (remoteCertBuffer == NULL)
    {
        printf("verifySigmaMessage #%d failed - Error allocating memory for remote certificate\n", messageType);
        return false;
    }
    memcpy(remoteCertBuffer, parts[1].part, parts[1].partSize);

    // 3. Validate signature size
    if (parts[2].partSize != SIGNATURE_SIZE_BYTES)
    {
        printf("verifySigmaMessage #%d failed - Signature size is wrong\n", messageType);
        return false;
    }

    // 4. Validate MAC size
    if (parts[3].partSize != HMAC_SIZE_BYTES)
    {
        printf("verifySigmaMessage #%d failed - MAC size is wrong\n", messageType);
        return false;
    }

    // Read the root CA certificate to verify the remote certificate
    ByteSmartPtr rootCACertBuffer = Utils::readBufferFromFile(_rootCaCertFilename);
    if (rootCACertBuffer == NULL)
    {
        printf("verifySigmaMessage #%d failed - Error reading root CA certificate: %s\n",
               messageType, _rootCaCertFilename);
        return false;
    }

    // Verify the certificate against the root CA and check expected identity
    if (!CryptoWrapper::checkCertificate(
            rootCACertBuffer, rootCACertBuffer.size(),
            remoteCertBuffer, remoteCertBuffer.size(),
            _expectedRemoteIdentityString))
    {
        printf("verifySigmaMessage #%d failed - Certificate verification failed\n", messageType);
        return false;
    }

    // Extract the public key from the verified certificate
    KeypairContext* remotePublicKeyContext = NULL;
    if (!CryptoWrapper::getPublicKeyFromCertificate(
            remoteCertBuffer, remoteCertBuffer.size(),
            &remotePublicKeyContext))
    {
        printf("verifySigmaMessage #%d failed - Error extracting public key from certificate\n", messageType);
        return false;
    }

    // Concatenate the public keys in the correct order for signature verification
    ByteSmartPtr concatenatedPublicKeysSmartPtr;
    if (messageType == 2)
    {
        // Verifying server message (client side)
        // Public keys order: client | server
        concatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                              _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }
    else // messageType == 3
    {
        // Verifying client message (server side)
        // Public keys order: client | server
        concatenatedPublicKeysSmartPtr = concat(2, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                              _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }

    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("verifySigmaMessage #%d failed - Error concatenating public keys for verification\n", messageType);
        CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);
        return false;
    }

    // Verify the signature over the concatenated public keys
    bool signatureValid = false;
    if (!CryptoWrapper::verifyMessageRsa3072Pss(
            concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(),
            remotePublicKeyContext, parts[2].part, parts[2].partSize,
            &signatureValid))
    {
        printf("verifySigmaMessage #%d failed - Error during signature verification\n", messageType);
        CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);
        return false;
    }

    if (!signatureValid)
    {
        printf("verifySigmaMessage #%d failed - Invalid signature\n", messageType);
        CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);
        return false;
    }

    // Clean up the remote public key context
    CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);

    // For message 3 (client), calculate shared secret
    if (messageType == 3)
    {
        // Calculate shared secret
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                             _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("verifySigmaMessage #%d failed - Error calculating shared secret\n", messageType);
            return false;
        }
    }

    // Verify the MAC over the remote certificate
    BYTE macKey[HMAC_SIZE_BYTES];
    deriveMacKey(macKey);

    BYTE calculatedMac[HMAC_SIZE_BYTES];
    if (!CryptoWrapper::hmac_SHA256(macKey, HMAC_SIZE_BYTES,
                                   remoteCertBuffer, remoteCertBuffer.size(),
                                   calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("verifySigmaMessage #%d failed - Error calculating MAC for verification\n", messageType);
        Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);
        return false;
    }

    Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);

    // Compare the calculated MAC with the received MAC
    if (memcmp(calculatedMac, parts[3].part, HMAC_SIZE_BYTES) != 0)
    {
        printf("verifySigmaMessage #%d failed - MAC verification failed\n", messageType);
        return false;
    }

    return true;
}
// bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
// {
//     if (messageType != 2 && messageType != 3)
//     {
//         return 0;
//     }
//
//     unsigned int expectedNumberOfParts = 4;
//     unsigned int partIndex = 0;
//
//     // We are expecting 4 parts
//     // 1: Remote public DH key (in message type 3 we will check that it equalss the value received in message type 1)
//     // 2: Remote certificate (PEM) null terminated
//     // 3: Signature over concatenated public keys (remote|local)
//     // 4: MAC over remote certificate with the shared MAC key
//
//     std::vector<MessagePart> parts;
//     if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
//     {
//         printf("verifySigmaMessage #%d failed - number of message parts is wrong\n", messageType);
//         return false;
//     }
//
//     // ...
//
//     // we will now verify if the received certificate belongs to the expected remote entity
//     // ...
//
//     // now we will verify if the signature over the concatenated public keys is ok
//     // ...
//
//     if (messageType == 2)
//     {
//         // Now we will calculate the shared secret
//         // ...
//
//     }
//
//     // Now we will verify the MAC over the certificate
//     // ...
//
//     return false;
// }
//


ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize)
{
    // If we have a session key, encrypt the message
    if (_sessionKey[0] != 0)  // Check if we have a valid session key
    {
        // Calculate the size needed for the encrypted message
        size_t ciphertextSize = CryptoWrapper::getCiphertextSizeAES_GCM256(messageSize);
        BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(ciphertextSize);
        if (ciphertext == NULL)
        {
            return NULL;
        }

        // Use message type and session ID as additional authenticated data (AAD)
        // This binds the encrypted data to the specific session and message type
        MessageHeader aadHeader;
        aadHeader.sessionId = _sessionId;
        aadHeader.messageType = messageType;
        aadHeader.messageCounter = _outgoingMessageCounter;
        aadHeader.payloadSize = (unsigned int)messageSize;

        size_t actualCiphertextSize = 0;
        if (!CryptoWrapper::encryptAES_GCM256(
            _sessionKey, SYMMETRIC_KEY_SIZE_BYTES,
            message, messageSize,
            (const BYTE*)&aadHeader, sizeof(aadHeader),
            ciphertext, ciphertextSize, &actualCiphertextSize))
        {
            printf("Error encrypting message\n");
            Utils::freeBuffer(ciphertext);
            return NULL;
        }

        ByteSmartPtr result(ciphertext, actualCiphertextSize);
        return result;
    }
    else
    {
        // Fallback to plain copy if no session key is available
        // (This should not happen in a secure implementation)
        printf("Warning: sending unencrypted message - no session key available\n");
        size_t encryptedMessageSize = messageSize;
        BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(encryptedMessageSize);
        if (ciphertext == NULL)
        {
            return NULL;
        }

        if (message != NULL && messageSize > 0)
        {
            memcpy_s(ciphertext, encryptedMessageSize, message, messageSize);
        }

        ByteSmartPtr result(ciphertext, encryptedMessageSize);
        return result;
    }
}
// ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize)
// {
//     // we will do a plain copy for now
//     size_t encryptedMessageSize = messageSize;
//     BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(encryptedMessageSize);
//     if (ciphertext == NULL)
//     {
//         return NULL;
//     }
//
//     memcpy_s(ciphertext, encryptedMessageSize, message, messageSize);
//
//     ByteSmartPtr result(ciphertext, encryptedMessageSize);
//     return result;
// }

bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
{
    // If we have a session key, decrypt the message
    if (_sessionKey[0] != 0)  // Check if we have a valid session key
    {
        size_t ciphertextSize = header->payloadSize;

        // Create a temporary buffer for the plaintext
        size_t expectedPlaintextSize = CryptoWrapper::getPlaintextSizeAES_GCM256(ciphertextSize);
        BYTE* plaintext = (BYTE*)Utils::allocateBuffer(expectedPlaintextSize);
        if (plaintext == NULL)
        {
            return false;
        }

        // Use message header as additional authenticated data (AAD)
        // This verifies the integrity of the session ID, message type, and counter
        MessageHeader aadHeader;
        aadHeader.sessionId = header->sessionId;
        aadHeader.messageType = header->messageType;
        aadHeader.messageCounter = header->messageCounter;
        aadHeader.payloadSize = 0;  // Will be filled by decryption

        size_t actualPlaintextSize = 0;
        bool result = CryptoWrapper::decryptAES_GCM256(
            _sessionKey, SYMMETRIC_KEY_SIZE_BYTES,
            buffer, ciphertextSize,
            (const BYTE*)&aadHeader, sizeof(aadHeader),
            plaintext, expectedPlaintextSize, &actualPlaintextSize);

        if (!result)
        {
            printf("Error decrypting message\n");
            Utils::secureCleanMemory(plaintext, expectedPlaintextSize);
            Utils::freeBuffer(plaintext);
            return false;
        }

        // Copy the decrypted data back to the input buffer
        memcpy_s(buffer, ciphertextSize, plaintext, actualPlaintextSize);

        // Clean up the temporary buffer
        Utils::secureCleanMemory(plaintext, expectedPlaintextSize);
        Utils::freeBuffer(plaintext);

        if (pPlaintextSize != NULL)
        {
            *pPlaintextSize = actualPlaintextSize;
        }

        return true;
    }
    else
    {
        // Fallback to plain copy if no session key is available
        // (This should not happen in a secure implementation)
        printf("Warning: receiving unencrypted message - no session key available\n");
        size_t ciphertextSize = header->payloadSize;
        size_t plaintextSize = ciphertextSize;

        if (pPlaintextSize != NULL)
        {
            *pPlaintextSize = plaintextSize;
        }

        return true;
    }
}
// bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
// {
//     // we will do a plain copy for now
//     size_t ciphertextSize = header->payloadSize;
//     size_t plaintextSize = ciphertextSize;
//
//
//     if (pPlaintextSize != NULL)
//     {
//         *pPlaintextSize = plaintextSize;
//     }
//
//     return true;
// }
//

bool Session::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        return false;
    }

    return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
}


ByteSmartPtr Session::concat(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += messagePart.partSize;
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by the smart pointer logic)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


ByteSmartPtr Session::packMessageParts(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += (messagePart.partSize + sizeof(size_t));
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by caller's smart pointer)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    std::list<MessagePart>::iterator it = partsList.begin();
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (; it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, (void*)&(it->partSize), sizeof(size_t));
        pos += sizeof(size_t);
        spaceLeft -= sizeof(size_t);
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


bool Session::unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result)
{
    std::list<MessagePart> partsList;
    size_t pos = 0;
    while (pos < bufferSize)
    {
        if (pos + sizeof(size_t) >= bufferSize)
        {
            return false;
        }

        size_t* partSize = (size_t*)(buffer + pos);
        pos += sizeof(size_t);
        if (*partSize == 0 || (pos + *partSize) > bufferSize)
            return false;

        MessagePart messagePart;
        messagePart.partSize = *partSize;
        messagePart.part = (buffer + pos);
        partsList.push_back(messagePart);
        pos += *partSize;
    }

    result.resize(partsList.size());
    unsigned int i = 0;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        result[i].part = it->part;
        result[i].partSize = it->partSize;
        i++;
    }
    return true;
}















