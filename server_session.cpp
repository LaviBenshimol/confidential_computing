#include <cstring>
#include <cstdio>
#include "server_session.h"
#include "utils.h"

#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


ServerSession::ServerSession(unsigned int localPort, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity):Session(keyFilename, password, certFilename, rootCaFilename, peerIdentity)
{
    _nextSessionId = 1;
    if (!active())
    {
        return;
    }

    struct sockaddr_in localAddress;
    memset(&localAddress, 0, sizeof(sockaddr_in));

    localAddress.sin_family = AF_INET;
    localAddress.sin_port = htons(localPort);
    localAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (!_localSocket->bindIpAddress(&localAddress))
    {
        _state = UNINITIALIZED_SESSION_STATE;
        return;
    }

    _state = INITIALIZED_SESSION_STATE;
    return;
}


ServerSession::ServerSession(const ServerSession& other, unsigned int id, unsigned int incomingCounter, unsigned int outgoingCounter, unsigned int state):Session(other)
{
    _nextSessionId = 1;
    _state = state;
    _sessionId = id;
    _incomingMessageCounter = incomingCounter;
    _outgoingMessageCounter = outgoingCounter;
}


ServerSession::~ServerSession()
{
    for (std::map<unsigned int, ServerSession*>::iterator it = _activeSessions.begin(); it != _activeSessions.end(); it++)
    {
        ServerSession* childSession = it->second;
        childSession->closeSession(); // sends GOODBYE message
        delete childSession;
    }
    _activeSessions.clear();
    destroySession();
}


Session::ReceiveResult ServerSession::receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize, ServerSession** ppChildSession, unsigned int* pChildSessionId)
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
        printf("Error during server receive\n");
        _state = UNINITIALIZED_SESSION_STATE;
        cleanDhData();
        return RR_FATAL_ERROR;
    }

    if (recvSize < sizeof(MessageHeader))
    {
        printf("Error during receive - message smaller than header\n");
        return RR_BAD_MESSAGE;
    }

    MessageHeader* header = (MessageHeader*)buffer;

    if (header->messageType < FIRST_SESSION_MESSAGE_TYPE || header->messageType > LAST_SESSION_MESSAGE_TYPE)
    {
        printf("Error during receive - bad message type, %d\n", header->messageType);
        return RR_BAD_MESSAGE;
    }

    if (header->payloadSize != recvSize - sizeof(MessageHeader))
    {
        printf("Error during receive - message size mismatch\n");
        return RR_BAD_MESSAGE;
    }

    if (header->sessionId == 0) // new session
    {
        if (header->messageType != HELLO_SESSION_MESSAGE || header->messageCounter != 0 || header->payloadSize != DH_KEY_SIZE_BYTES)
        {
            printf("Error during receive - message type mismatch with session id of 0\n");
            return RR_BAD_MESSAGE;
        }

        ServerSession* newSession = new ServerSession(*this, _nextSessionId, 1, 0, HELLO_SESSION_MESSAGE);
        memcpy_s(&(newSession->_remoteAddress), sizeof(struct sockaddr_in), &remoteAddr, remoteAddrSize);

        // here we will prepare DH message 2
        // ...
        /*
        ByteSmartPtr message2 = newSession->prepareSigmaMessage(2);
        if (message2 == NULL)
        {
            return RR_FATAL_ERROR;
        }
		*/

        if (!newSession->sendMessageInternal(HELLO_BACK_SESSION_MESSAGE, NULL, 0))
        {
            printf("Error during receive - error sending response to new session\n");
            newSession->cleanDhData();
            return RR_FATAL_ERROR;
        }

        newSession->_state = HELLO_BACK_SESSION_MESSAGE;

        _nextSessionId++;
        std::pair<std::map<unsigned int, ServerSession*>::iterator, bool> ret;
        ret = _activeSessions.insert(std::pair <unsigned int, ServerSession*>(newSession->_sessionId, newSession) );
        std::map<unsigned int, ServerSession*>::iterator it = ret.first;

        if (ppChildSession)
        {
            *ppChildSession = it->second;
        }
        if (pChildSessionId)
        {
            *pChildSessionId = it->second->id();
        }
        printf("New session %d created with %s\n", newSession->_sessionId, newSession->_expectedRemoteIdentityString != NULL ? newSession->_expectedRemoteIdentityString : "a valid peer");

        if (ppPayload != NULL)
        {
            *ppPayload = NULL;
        }

        if (pPayloadSize != NULL)
        {
            *pPayloadSize = 0;
        }

        return RR_PROTOCOL_MESSAGE;
    }
    else // existing session
    {
        std::map<unsigned int, ServerSession*>::iterator it = _activeSessions.find(header->sessionId);
        if (it != _activeSessions.end())
        {
            ServerSession* pSession = it->second;
            if (ppChildSession)
            {
                *ppChildSession = pSession;
            }
            if (pChildSessionId)
            {
                *pChildSessionId = pSession->id();
            }
            if (!pSession->active())
            {
                printf("Error during receive - received message for non-active session\n");
                return RR_BAD_MESSAGE;
            }

            if (header->messageCounter != pSession->_incomingMessageCounter)
            {
                printf("Error during receive - message counter mismatch\n");
                return RR_BAD_MESSAGE;
            }

            switch (header->messageType)
            {
            case GOODBYE_SESSION_MESSAGE:
            {
                size_t plaintextSize = 0;
                if (!pSession->decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
                {
                    return RR_BAD_MESSAGE;
                }
                printf("Session close request received, closing session %d\n", pSession->_sessionId);
               
                if (ppChildSession)
                {
                    *ppChildSession = NULL;
                }
                delete pSession;
                _activeSessions.erase(header->sessionId);

                if (ppPayload != NULL)
                {
                    *ppPayload = NULL;
                }

                if (pPayloadSize != NULL)
                {
                    *pPayloadSize = 0;
                }

                return RR_SESSION_CLOSED;
            }
            case HELLO_DONE_SESSION_MESSAGE:
                if (pSession->_state == HELLO_BACK_SESSION_MESSAGE)
                {
                    BYTE* pPayload = buffer + sizeof(MessageHeader);
                    // here we need to verify SIGMA message 3
					/*
                    if (!pSession->verifySigmaMessage(3, pPayload, (size_t)header->payloadSize))
                    {
                        printf("Session crypto error, closing session %d\n", pSession->_sessionId);
                        pSession->cleanDhData();
                        delete pSession;
                        _activeSessions.erase(header->sessionId);
                        return RR_SESSION_CLOSED;
                    }
					*/

                    // now we will calculate the session key
                    pSession->deriveSessionKey();
                    pSession->_state = DATA_SESSION_MESSAGE;
                    pSession->_incomingMessageCounter++;

                    if (ppPayload != NULL)
                    {
                        *ppPayload = NULL;
                    }

                    if (pPayloadSize != NULL)
                    {
                        *pPayloadSize = 0;
                    }

                    return RR_NEW_SESSION_CREATED;
                }
                else
                {
                    return RR_BAD_MESSAGE;
                }
            case DATA_SESSION_MESSAGE:
                if (pSession->_state == DATA_SESSION_MESSAGE)
                {
                    size_t plaintextSize = 0;
                    if (!pSession->decryptMessage(header, buffer + sizeof(MessageHeader), &plaintextSize))
                    {
                        return RR_BAD_MESSAGE;
                    }

                    pSession->_incomingMessageCounter++;

                    if (ppPayload != NULL)
                    {
                        *ppPayload = buffer + sizeof(MessageHeader);
                    }
                    
                    if (pPayloadSize != NULL)
                    {
                        *pPayloadSize = plaintextSize;
                    }

                    return RR_DATA_MESSAGE;
                }
                else
                {
                    return RR_BAD_MESSAGE;
                }
            };
        }
        else
        {
            return RR_BAD_MESSAGE;
        }
    }

    return RR_BAD_MESSAGE;
}


void ServerSession::closeChildSession(unsigned int sessionId)
{
    std::map<unsigned int, ServerSession*>::iterator it = _activeSessions.find(sessionId);
    if (it != _activeSessions.end())
    {
        ServerSession* session = it->second;
        session->closeSession();
        delete session;
        _activeSessions.erase(it);
    }
}