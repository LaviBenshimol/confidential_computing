#ifndef SESSION_H
#define SESSION_H

#include <stddef.h>
#include <vector>
#include "sockets.h"
#include "crypto_wrapper.h"
#include "session_internals.h"


//                               Protocol overview
/* ****************************************************************************************************
* 
*                                                              Server - initSession(local port) 
*                                                              Server - serverReceiveMessage()
* 
* Client - initSession(remote ip and port)
* 
*               ------------------ HELLO_MESSAGE ----------------->
* 
*                                                              (new client session object created)
* 
*               <--------------- HELLO_BACK_MESSAGE ---------------
*
*               ---------------- HELLO_DONE_MESSAGE -------------->
* 
*                                                              (client session object ready for data)
* 
* Client - sendSessionMessage(message)
* 
*               -------------- DATA_MESSAGE (Payload) ------------>
* 
* Client - clientReceiveMessage()
*                                                              Server - sendSessionMessage(message)
*
*               <------------- DATA_MESSAGE (Payload) -------------
* 
*                                                              Server - serverReceiveMessage()
*               ...
*
* Client - sendSessionMessage(message)
*
*               -------------- DATA_MESSAGE (Payload) ------------>
*
* Client - clientReceiveMessage()
*                                                              Server - sendSessionMessage(message)
*
*               <------------- DATA_MESSAGE (Payload) -------------
*
*                                                              Server - serverReceiveMessage()
*
* 
* Client - closeSession(session)
*
*               ---------------- GOODBYE_MESSAGE ----------------->
*                                                              (client session object destroyed)
* 
*******************************************************************************************************/





class Session
{
public:
    
    enum ReceiveResult
    {
        RR_DATA_MESSAGE,
        RR_PROTOCOL_MESSAGE,
        RR_BAD_MESSAGE,
        RR_FATAL_ERROR,
        RR_NEW_SESSION_CREATED,
        RR_SESSION_CLOSED,
        RR_TIMEOUT
    };

    class MessagePart
    {
    public:
        const BYTE* part;
        size_t partSize;
    };
    
    bool active();

    unsigned int id() { return _sessionId; }

    // Send Data message
    bool sendDataMessage(const BYTE* message, size_t messageSize);

    // Concatenates the provided buffers into one buffer
    // Provide buffer pointer and size for each part to concatenate
    static ByteSmartPtr concat(unsigned int numOfParts, ...);

    // Concatenates the provided buffers into one buffer, while adding each buffer size as part of the result to enable unpacking
    // Provide buffer pointer and size for each part to concatenate
    static ByteSmartPtr packMessageParts(unsigned int numOfParts, ...);

    // Retruns a vector of MessageParts. 
    // Each MessagePart has pointer to buffer and buffer size
    static bool unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result);

    static constexpr size_t MESSAGE_BUFFER_SIZE_BYTES = 10000;

protected:
    unsigned int _state; // session state
    unsigned int _sessionId; // given by the server
    Socket* _localSocket; 
    struct sockaddr_in _remoteAddress;
    unsigned int _outgoingMessageCounter;
    unsigned int _incomingMessageCounter;

    ReferenceCounter* _pReferenceCounter;

    // additional session properties can be added here
    // e.g. remote identity, crypto, ...
    const char* _privateKeyFilename;
    char* _privateKeyPassword;
    const char* _localCertFilename;
    const char* _rootCaCertFilename;
    const char* _expectedRemoteIdentityString;

    BYTE _sessionKey[SYMMETRIC_KEY_SIZE_BYTES];
    DhContext* _dhContext;
    BYTE _localDhPublicKeyBuffer[DH_KEY_SIZE_BYTES];
    BYTE _remoteDhPublicKeyBuffer[DH_KEY_SIZE_BYTES];
    BYTE _sharedDhSecretBuffer[DH_KEY_SIZE_BYTES];

    Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity);
    Session(const Session& other);
    void setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort);
    void prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize);
    bool sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize);
    void cleanDhData();
    void deriveMacKey(BYTE* macKeyBuffer);
    void deriveSessionKey();
    bool verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize);
    ByteSmartPtr prepareSigmaMessage(unsigned int messageType);
    ByteSmartPtr prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize);
    bool decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize);
    void closeSession();
    void destroySession();

    // Protocol Message types and session states
    static constexpr unsigned int UNINITIALIZED_SESSION_STATE   = 0;
    static constexpr unsigned int INITIALIZED_SESSION_STATE     = 1;
    static constexpr unsigned int DEACTIVATED_SESSION_STATE     = 7;

    static constexpr unsigned int HELLO_SESSION_MESSAGE         = 2;
    static constexpr unsigned int HELLO_BACK_SESSION_MESSAGE    = 3;
    static constexpr unsigned int HELLO_DONE_SESSION_MESSAGE    = 4;
    static constexpr unsigned int GOODBYE_SESSION_MESSAGE       = 5;
    static constexpr unsigned int DATA_SESSION_MESSAGE          = 6;

    static constexpr unsigned int FIRST_SESSION_MESSAGE_TYPE    = HELLO_SESSION_MESSAGE;
    static constexpr unsigned int LAST_SESSION_MESSAGE_TYPE     = DATA_SESSION_MESSAGE;
};


#endif // #ifndef SESSION_H
