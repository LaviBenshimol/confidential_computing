#include <stdio.h>
#include <cstring>
#include "client_session.h"



ClientSession::ClientSession(unsigned int remotePort, const char* remoteIpAddress, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity):Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
{
    if (!active())
    {
        return;
    }

    setRemoteAddress(remoteIpAddress, remotePort);

    // Perhaps we can use the first message as Sigma message #1?
    BYTE dummy[DH_KEY_SIZE_BYTES];
    if (!sendMessageInternal(HELLO_SESSION_MESSAGE, dummy, DH_KEY_SIZE_BYTES))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }
    _state = HELLO_SESSION_MESSAGE;

    BYTE messageBuffer[MESSAGE_BUFFER_SIZE_BYTES];
    memset(messageBuffer, '\0', MESSAGE_BUFFER_SIZE_BYTES);

    BYTE* pPayload = NULL;
    size_t payloadSize = 0;
    bool rcvResult = receiveMessage(messageBuffer, MESSAGE_BUFFER_SIZE_BYTES, 10, &pPayload, &payloadSize);
    if (!rcvResult || _state != HELLO_BACK_SESSION_MESSAGE)
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // here we need to verify the DH message 2 part
	/*
    if (!verifySigmaMessage(2, pPayload, (size_t)payloadSize))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }
	*/

    // send SIGMA message 3 part
    /*
	ByteSmartPtr message3 = prepareSigmaMessage(3);
    if (message3 == NULL)
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }
	*/

    if (!sendMessageInternal(HELLO_DONE_SESSION_MESSAGE, NULL, 0))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return;
    }

    // now we will calculate the session key
    deriveSessionKey();

    _state = DATA_SESSION_MESSAGE;
    return;
}


ClientSession::~ClientSession()
{
    closeSession();
    destroySession();
}


Session::ReceiveResult ClientSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize)
{
    if (!active())
    {
        return RR_FATAL_ERROR;
    }

    struct sockaddr_in remoteAddr;
    int remoteAddrSize = sizeof(remoteAddr);
    memset(&remoteAddr, 0, remoteAddrSize);

    size_t recvSize = 0;
    Socket::ReceiveResult rcvResult = _localSocket->receive(buffer, bufferSize, timeout_sec, &recvSize, &remoteAddr);
    switch (rcvResult)
    {
    case Socket::RR_TIMEOUT:
        return RR_TIMEOUT;
    case Socket::RR_ERROR:
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return RR_FATAL_ERROR;
    }

    if (recvSize < sizeof(MessageHeader))
    {
        return RR_BAD_MESSAGE;
    }

    MessageHeader* header = (MessageHeader*)buffer;
    if (header->messageType < FIRST_SESSION_MESSAGE_TYPE || header->messageType > LAST_SESSION_MESSAGE_TYPE)
    {
        return RR_BAD_MESSAGE;
    }

    if (header->payloadSize != recvSize - sizeof(MessageHeader))
    {
        return RR_BAD_MESSAGE;
    }

    if (header->messageCounter != _incomingMessageCounter)
    {
        return RR_BAD_MESSAGE;
    }

    _incomingMessageCounter++;

    switch (header->messageType)
    {
    case GOODBYE_SESSION_MESSAGE:
        return RR_SESSION_CLOSED;
    case HELLO_SESSION_MESSAGE:
        return RR_BAD_MESSAGE;
    case HELLO_BACK_SESSION_MESSAGE:
        if (_state == HELLO_SESSION_MESSAGE)
        {
            _sessionId = header->sessionId;
            _state = HELLO_BACK_SESSION_MESSAGE;

            if (ppPayload != NULL)
                *ppPayload = buffer + sizeof(MessageHeader);

            if (pPayloadSize != NULL)
                *pPayloadSize = header->payloadSize;

            printf("Session started with %s\n", _expectedRemoteIdentityString);
            return RR_PROTOCOL_MESSAGE;
        }
        else
        {
            return RR_BAD_MESSAGE;
        }
    case DATA_SESSION_MESSAGE:
        if (_state == DATA_SESSION_MESSAGE)
        {
            size_t plaintextSize = 0;
            if (!decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
            {
                return RR_BAD_MESSAGE;
            }

            if (ppPayload != NULL)
            {
                *ppPayload = buffer + sizeof(MessageHeader);
            }

            if (pPayloadSize != NULL)
            {
                *pPayloadSize = plaintextSize;
            }
            _state = DATA_SESSION_MESSAGE;
            return RR_DATA_MESSAGE;
        }
        else
            return RR_BAD_MESSAGE;
    }

    return RR_BAD_MESSAGE;
}