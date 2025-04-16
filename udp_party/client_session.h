#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include "session.h"

class ClientSession : public Session
{
public:
	ClientSession(unsigned int remotePort, const char* remoteIpAddress, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity);

	~ClientSession();

	// Wait to receive a message
	ReceiveResult receiveMessage(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, BYTE** ppPayload, size_t* pPayloadSize);

private:	
};


#endif // #ifndef CLIENT_SESSION_H
