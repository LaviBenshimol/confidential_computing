#ifndef SOCKETS_H
#define SOCKETS_H

#ifdef WIN
#include <winsock2.h>
#else // #ifdef WIN
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif // #ifdef WIN

#include "types.h"


class Socket
{
public:

	enum ReceiveResult
	{
		RR_OK,
		RR_ERROR,
		RR_TIMEOUT
	};

	Socket(unsigned int localPort);

	~Socket();

	bool bindIpAddress(struct sockaddr_in* ipAddress);

	bool send(const BYTE* message, size_t messageSize, struct sockaddr_in* remoteAddr);

	ReceiveResult receive(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, size_t* pReceivedSize, struct sockaddr_in* remoteAddr);

	bool valid();

private:

	int _socketFD;

	static bool _socketsInitDone;
	
	bool initSockets();

	void closeSocket();
};



#endif // #ifndef SOCKETS_H
