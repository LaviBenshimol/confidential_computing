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
    // Create a deterministic context string that includes the session ID
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "SIGMA-MAC-%d", _sessionId) <= 0)
    {
        printf("SIGMA: Error creating key derivation context\n");
        exit(0);
    }

    // Use a fixed salt of all zeros
    // This ensures both sides derive the same key
    BYTE salt[HMAC_SIZE_BYTES] = {0};

    printf("SIGMA: MAC key derivation parameters:\n");
    printf("- Context: %s\n", keyDerivationContext);
    printf("- Shared secret (first 8 bytes): ");
    for (int i = 0; i < 8 && i < DH_KEY_SIZE_BYTES; i++) {
        printf("%02x", _sharedDhSecretBuffer[i]);
    }
    printf("\n");

    // Derive the MAC key using HKDF with the shared DH secret
    if (!CryptoWrapper::deriveKey_HKDF_SHA256(
            salt, HMAC_SIZE_BYTES,  // Fixed salt (all zeros)
            _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES,  // Input key material (shared DH secret)
            (const BYTE*)keyDerivationContext, strnlen_s(keyDerivationContext, MAX_CONTEXT_SIZE),  // Context
            macKeyBuffer, HMAC_SIZE_BYTES))  // Output key
    {
        printf("SIGMA: Error during MAC key derivation\n");
        exit(0);
    }

    printf("SIGMA: Derived MAC key (first 8 bytes): ");
    for (int i = 0; i < 8 && i < HMAC_SIZE_BYTES; i++) {
        printf("%02x", macKeyBuffer[i]);
    }
    printf("\n");
}

void Session::deriveSessionKey()
{
    // Create a deterministic context string that includes the session ID
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "SIGMA-ENC-%d", _sessionId) <= 0)
    {
        printf("SIGMA: Error creating session key derivation context\n");
        exit(0);
    }

    // Use a fixed salt of all zeros
    BYTE salt[HMAC_SIZE_BYTES] = {0};

    printf("SIGMA: Session key derivation parameters:\n");
    printf("- Context: %s\n", keyDerivationContext);
    printf("- Shared secret (first 8 bytes): ");
    for (int i = 0; i < 8 && i < DH_KEY_SIZE_BYTES; i++) {
        printf("%02x", _sharedDhSecretBuffer[i]);
    }
    printf("\n");

    // Derive the session key using HKDF with the DH shared secret
    if (!CryptoWrapper::deriveKey_HKDF_SHA256(
            salt, HMAC_SIZE_BYTES,
            _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES,
            (const BYTE*)keyDerivationContext, strnlen_s(keyDerivationContext, MAX_CONTEXT_SIZE),
            _sessionKey, SYMMETRIC_KEY_SIZE_BYTES))
    {
        printf("SIGMA: Error during session key derivation\n");
        exit(0);
    }

    printf("SIGMA: Derived session key (first 8 bytes): ");
    for (int i = 0; i < 8 && i < SYMMETRIC_KEY_SIZE_BYTES; i++) {
        printf("%02x", _sessionKey[i]);
    }
    printf("\n");

    printf("SIGMA: Session key derivation complete\n");
}

ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    // SIGMA protocol only defines messages 2 and 3
    if (messageType != 2 && messageType != 3)
    {
        printf("prepareSigmaMessage: Invalid message type %d\n", messageType);
        return NULL;
    }

    printf("SIGMA: Preparing message %d\n", messageType);

    // ------ STEP 1: Initialize DH for message 2 (server only) ------
    // For message 2 (server), we need to initialize our DH context and generate our public key
    // For message 3 (client), we already have our DH key from the initial hello message
    if (messageType == 2)
    {
        printf("SIGMA: Server generating DH key pair\n");
        // Initialize DH and get our public key
        if (!CryptoWrapper::startDh(&_dhContext, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("SIGMA: Failed to initialize DH key exchange\n");
            return NULL;
        }
    }

    // ------ STEP 2: Get my certificate for inclusion in the message ------
    printf("SIGMA: Reading local certificate: %s\n", _localCertFilename);
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        printf("SIGMA: Error reading certificate file: %s\n", _localCertFilename);
        return NULL;
    }

    // ------ STEP 3: Load my private signing key ------
    printf("SIGMA: Reading private key: %s\n", _privateKeyFilename);
    KeypairContext* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        printf("SIGMA: Error loading private key: %s\n", _privateKeyFilename);
        return NULL;
    }

    // ------ STEP 4: Concatenate public keys in the correct order for signing ------
    // SIGMA protocol requires signing the concatenation of both public keys
    // The order is based on message type to ensure consistency when verifying
    ByteSmartPtr concatenatedPublicKeysSmartPtr = NULL;
    if (messageType == 2)
    {
        // Server: order is client DH key | server DH key
        printf("SIGMA: Concatenating keys in order: client|server for signature\n");
        concatenatedPublicKeysSmartPtr = concat(2,
                                               _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                               _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }
    else // messageType == 3
    {
        // Client: order is client DH key | server DH key (same order)
        printf("SIGMA: Concatenating keys in order: client|server for signature\n");
        concatenatedPublicKeysSmartPtr = concat(2,
                                               _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                               _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }

    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("SIGMA: Failed to concatenate DH public keys\n");
        CryptoWrapper::cleanKeyContext(&privateKeyContext);
        return NULL;
    }

    // ------ STEP 5: Sign the concatenated public keys with my private key ------
    printf("SIGMA: Signing concatenated DH public keys\n");
    BYTE signature[SIGNATURE_SIZE_BYTES];
    if (!CryptoWrapper::signMessageRsa3072Pss(
            concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(),
            privateKeyContext, signature, SIGNATURE_SIZE_BYTES))
    {
        printf("SIGMA: Failed to create signature\n");
        CryptoWrapper::cleanKeyContext(&privateKeyContext);
        return NULL;
    }

    // Clean up the private key context - we don't need it anymore
    CryptoWrapper::cleanKeyContext(&privateKeyContext);

    // ------ STEP 6: For message 2 (server), calculate the shared DH secret ------
    if (messageType == 2)
    {
        printf("SIGMA: Server calculating shared DH secret\n");
        // Calculate shared secret based on received client public key
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                             _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("SIGMA: Failed to calculate shared DH secret\n");
            return NULL;
        }

        printf("SIGMA: Server shared secret (first 8 bytes): ");
        for (int i = 0; i < 8 && i < DH_KEY_SIZE_BYTES; i++) {
            printf("%02x", _sharedDhSecretBuffer[i]);
        }
        printf("\n");
    }

    // ------ STEP 7: Derive the MAC key from the shared secret ------
    printf("SIGMA: Deriving MAC key from shared secret\n");
    BYTE macKey[HMAC_SIZE_BYTES];
    deriveMacKey(macKey);

    // ------ STEP 8: Calculate the MAC over my certificate ------
    printf("SIGMA: Calculating MAC over certificate\n");
    BYTE calculatedMac[HMAC_SIZE_BYTES];
    if (!CryptoWrapper::hmac_SHA256(macKey, HMAC_SIZE_BYTES,
                                   certBufferSmartPtr, certBufferSmartPtr.size(),
                                   calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("SIGMA: Failed to calculate MAC\n");
        Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);
        return NULL;
    }

    // Securely clean the MAC key as we don't need it anymore
    Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);

    // ------ STEP 9: Pack all the message parts together ------
    printf("SIGMA: Packing the complete message\n");
    ByteSmartPtr messageToSend = packMessageParts(4,
                                               _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,   // Part 1: My DH public key
                                               (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), // Part 2: My certificate
                                               signature, SIGNATURE_SIZE_BYTES,              // Part 3: Signature over both keys
                                               calculatedMac, HMAC_SIZE_BYTES);              // Part 4: MAC over my certificate

    printf("SIGMA: Message %d preparation complete\n", messageType);
    return messageToSend;
}

bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    // SIGMA protocol only defines messages 2 and 3
    if (messageType != 2 && messageType != 3)
    {
        printf("SIGMA: Invalid message type %d for verification\n", messageType);
        return false;
    }

    printf("SIGMA: Verifying message %d\n", messageType);

    // ------ STEP 1: Unpack the received message parts ------
    const unsigned int expectedNumberOfParts = 4;
    std::vector<MessagePart> parts;

    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        printf("SIGMA: Wrong number of message parts - expected %d, got %zu\n",
               expectedNumberOfParts, parts.size());
        return false;
    }

    printf("SIGMA: Message unpacked successfully\n");

    // ------ STEP 2: Validate and extract the remote DH public key ------
    if (parts[0].partSize != DH_KEY_SIZE_BYTES)
    {
        printf("SIGMA: DH key size is wrong - expected %zu, got %zu\n",
               (size_t)DH_KEY_SIZE_BYTES, parts[0].partSize);
        return false;
    }

    // Store remote DH public key
    memcpy(_remoteDhPublicKeyBuffer, parts[0].part, DH_KEY_SIZE_BYTES);
    printf("SIGMA: Remote DH public key extracted\n");

    // ------ STEP 3: Copy the remote certificate ------
    ByteSmartPtr remoteCertBuffer((BYTE*)Utils::allocateBuffer(parts[1].partSize), parts[1].partSize);
    if (remoteCertBuffer == NULL)
    {
        printf("SIGMA: Failed to allocate memory for remote certificate\n");
        return false;
    }
    memcpy(remoteCertBuffer, parts[1].part, parts[1].partSize);
    printf("SIGMA: Remote certificate extracted\n");

    // ------ STEP 4: Validate signature and MAC sizes ------
    if (parts[2].partSize != SIGNATURE_SIZE_BYTES)
    {
        printf("SIGMA: Signature size is wrong - expected %zu, got %zu\n",
               (size_t)SIGNATURE_SIZE_BYTES, parts[2].partSize);
        return false;
    }

    if (parts[3].partSize != HMAC_SIZE_BYTES)
    {
        printf("SIGMA: MAC size is wrong - expected %zu, got %zu\n",
               (size_t)HMAC_SIZE_BYTES, parts[3].partSize);
        return false;
    }

    // ------ STEP 5: Verify the remote certificate against the root CA ------
    printf("SIGMA: Reading root CA certificate: %s\n", _rootCaCertFilename);
    ByteSmartPtr rootCACertBuffer = Utils::readBufferFromFile(_rootCaCertFilename);
    if (rootCACertBuffer == NULL)
    {
        printf("SIGMA: Failed to read root CA certificate: %s\n", _rootCaCertFilename);
        return false;
    }

    printf("SIGMA: Verifying remote certificate with expected identity: %s\n", _expectedRemoteIdentityString);
    if (!CryptoWrapper::checkCertificate(
            rootCACertBuffer, rootCACertBuffer.size(),
            remoteCertBuffer, remoteCertBuffer.size(),
            _expectedRemoteIdentityString))
    {
        printf("SIGMA: Certificate verification failed\n");
        return false;
    }
    printf("SIGMA: Certificate verification successful\n");

    // ------ STEP 6: Extract the public key from the verified certificate ------
    printf("SIGMA: Extracting public key from remote certificate\n");
    KeypairContext* remotePublicKeyContext = NULL;
    if (!CryptoWrapper::getPublicKeyFromCertificate(
            remoteCertBuffer, remoteCertBuffer.size(),
            &remotePublicKeyContext))
    {
        printf("SIGMA: Failed to extract public key from certificate\n");
        return false;
    }

    // ------ STEP 7: Concatenate the DH public keys in the correct order for signature verification ------
    ByteSmartPtr concatenatedPublicKeysSmartPtr = NULL;
    if (messageType == 2)
    {
        // Verifying server message (client side)
        // Public keys order: client | server
        printf("SIGMA: Concatenating keys in order: client|server for verification\n");
        concatenatedPublicKeysSmartPtr = concat(2,
                                              _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                              _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }
    else // messageType == 3
    {
        // Verifying client message (server side)
        // Public keys order: client | server
        printf("SIGMA: Concatenating keys in order: client|server for verification\n");
        concatenatedPublicKeysSmartPtr = concat(2,
                                              _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                              _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    }

    if (concatenatedPublicKeysSmartPtr == NULL)
    {
        printf("SIGMA: Failed to concatenate public keys for verification\n");
        CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);
        return false;
    }

    // ------ STEP 8: Verify the signature over the concatenated public keys ------
    printf("SIGMA: Verifying signature over concatenated DH public keys\n");
    bool signatureValid = false;
    if (!CryptoWrapper::verifyMessageRsa3072Pss(
            concatenatedPublicKeysSmartPtr, concatenatedPublicKeysSmartPtr.size(),
            remotePublicKeyContext, parts[2].part, parts[2].partSize,
            &signatureValid))
    {
        printf("SIGMA: Error during signature verification\n");
        CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);
        return false;
    }

    if (!signatureValid)
    {
        printf("SIGMA: Invalid signature\n");
        CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);
        return false;
    }
    printf("SIGMA: Signature verification successful\n");

    // Clean up the remote public key context
    CryptoWrapper::cleanKeyContext(&remotePublicKeyContext);

    // ------ STEP 9: Calculate the shared DH secret if needed ------
    // For message 2 (client verifying server), calculate shared secret if not done already
    // For message 3 (server verifying client), always calculate the shared secret
    if (messageType == 2 && _sharedDhSecretBuffer[0] == 0) // Check if shared secret appears uninitialized
    {
        printf("SIGMA: Client calculating shared DH secret\n");
        // Calculate shared secret
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                             _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("SIGMA: Failed to calculate shared DH secret\n");
            return false;
        }

        printf("SIGMA: Client shared secret (first 8 bytes): ");
        for (int i = 0; i < 8 && i < DH_KEY_SIZE_BYTES; i++) {
            printf("%02x", _sharedDhSecretBuffer[i]);
        }
        printf("\n");
    }
    else if (messageType == 3)
    {
        printf("SIGMA: Server calculating shared DH secret\n");
        // Calculate shared secret
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                             _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("SIGMA: Failed to calculate shared DH secret\n");
            return false;
        }

        printf("SIGMA: Server shared secret (first 8 bytes): ");
        for (int i = 0; i < 8 && i < DH_KEY_SIZE_BYTES; i++) {
            printf("%02x", _sharedDhSecretBuffer[i]);
        }
        printf("\n");
    }

    // ------ STEP 9: Calculate the shared DH secret if needed ------
    // For message 2 (client verifying server), calculate shared secret if not done already
    // For message 3 (server verifying client), always calculate the shared secret
    if (messageType == 2 && _sharedDhSecretBuffer[0] == 0) // Check if shared secret appears uninitialized
    {
        printf("SIGMA: Client calculating shared DH secret\n");
        // Calculate shared secret
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                             _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("SIGMA: Failed to calculate shared DH secret\n");
            return false;
        }

        printf("SIGMA: Client shared secret (first 8 bytes): ");
        for (int i = 0; i < 8 && i < DH_KEY_SIZE_BYTES; i++) {
            printf("%02x", _sharedDhSecretBuffer[i]);
        }
        printf("\n");
    }
    else if (messageType == 3)
    {
        printf("SIGMA: Server calculating shared DH secret\n");
        // Calculate shared secret
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES,
                                             _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("SIGMA: Failed to calculate shared DH secret\n");
            return false;
        }

        printf("SIGMA: Server shared secret (first 8 bytes): ");
        for (int i = 0; i < 8 && i < DH_KEY_SIZE_BYTES; i++) {
            printf("%02x", _sharedDhSecretBuffer[i]);
        }
        printf("\n");
    }


    // ------ STEP 10: Derive the MAC key from the shared secret ------
    printf("SIGMA: Deriving MAC key from shared secret\n");
    BYTE macKey[HMAC_SIZE_BYTES];
    deriveMacKey(macKey);

    // ------ STEP 11: Calculate the MAC over the remote certificate ------
    printf("SIGMA: Calculating MAC over certificate for verification\n");
    BYTE calculatedMac[HMAC_SIZE_BYTES];
    if (!CryptoWrapper::hmac_SHA256(macKey, HMAC_SIZE_BYTES,
                                   remoteCertBuffer, remoteCertBuffer.size(),
                                   calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("SIGMA: Failed to calculate MAC for verification\n");
        Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);
        return false;
    }

    // ------ STEP 12: Compare the calculated MAC with the received MAC ------
    printf("SIGMA: Comparing calculated MAC with received MAC\n");

    printf("SIGMA: Calculated MAC (first 8 bytes): ");
    for (int i = 0; i < 8 && i < HMAC_SIZE_BYTES; i++) {
        printf("%02x", calculatedMac[i]);
    }
    printf("\n");

    printf("SIGMA: Received MAC (first 8 bytes): ");
    for (int i = 0; i < 8 && i < HMAC_SIZE_BYTES; i++) {
        printf("%02x", parts[3].part[i]);
    }
    printf("\n");

    bool macValid = (memcmp(calculatedMac, parts[3].part, HMAC_SIZE_BYTES) == 0);
    Utils::secureCleanMemory(macKey, HMAC_SIZE_BYTES);

    if (!macValid)
    {
        printf("SIGMA: MAC verification failed\n");
        return false;
    }

    printf("SIGMA: MAC verification successful\n");
    printf("SIGMA: Message %d verification complete\n", messageType);
    return true;
}

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
        aadHeader.payloadSize = expectedPlaintextSize;
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















