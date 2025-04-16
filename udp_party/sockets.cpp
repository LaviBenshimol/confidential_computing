#ifdef WIN
#include <WS2tcpip.h>
#else // #ifdef WIN
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#endif // #ifdef WIN
#include "sockets.h"


#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


bool Socket::_socketsInitDone = false;


bool Socket::initSockets()
{
    if (!_socketsInitDone)
    {
#ifdef WIN
        WSADATA wsa;

        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return false;
#endif // #ifdef WIN

        _socketsInitDone = true;
    }

    return true;
}


bool Socket::valid()
{
    return _socketFD > 0 ;
}


Socket::Socket(unsigned int localPort)
{
    _socketFD = -1;
    if (!initSockets())
    {
        return;
    }

    _socketFD = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (_socketFD != -1 && localPort != 0)
    {
        struct sockaddr_in localAddress;
        memset(&localAddress, 0, sizeof(sockaddr_in));

        localAddress.sin_family = AF_INET;
        localAddress.sin_port = htons(localPort);
        localAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

        if (bind(_socketFD, (struct sockaddr*)&localAddress, sizeof(localAddress)) < 0)
        {
            closeSocket();
            _socketFD = -1;
        }
    }
}


Socket::~Socket()
{
    closeSocket();
}


void Socket::closeSocket()
{
#ifdef WIN
    closesocket(_socketFD);
#else // #ifdef WIN
    close(_socketFD);
#endif // #ifdef WIN
}


bool Socket::bindIpAddress(struct sockaddr_in* ipAddress)
{
    if (bind(_socketFD, (struct sockaddr*)ipAddress, sizeof(struct sockaddr_in)) < 0)
    {
        return false;
    }
    else
    {
        return true;
    }
}


bool Socket::send(const BYTE* message, size_t messageSize, struct sockaddr_in* remoteAddr)
{
    if (!valid())
    {
        return false;
    }

    size_t sentCount = sendto(_socketFD, (const char*)message, (int)messageSize, 0, (const struct sockaddr*)remoteAddr, sizeof(sockaddr_in));
    return (sentCount == messageSize);
}


Socket::ReceiveResult Socket::receive(BYTE* buffer, size_t bufferSize, unsigned int timeout_sec, size_t* pReceivedSize, struct sockaddr_in* remoteAddr)
{
    if (!valid())
    {
        return RR_ERROR;
    }

    socklen_t remoteAddrSize = sizeof(struct sockaddr_in);
    memset(remoteAddr, 0, remoteAddrSize);

#ifdef WIN
    unsigned int timeout_ms = timeout_sec * 1000;
    setsockopt(_socketFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
#else // #ifdef WIN
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(_socketFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
#endif // #ifdef WIN

    int rcvResult = recvfrom(_socketFD, (char*)buffer, (int)bufferSize, 0, (struct sockaddr*)remoteAddr, &remoteAddrSize);
    if (rcvResult == -1)
    {
        return RR_TIMEOUT;
    }

    if (rcvResult < 0)
    {
        return RR_ERROR;
    }
    
    if (pReceivedSize != NULL)
    {
        *pReceivedSize = (size_t)rcvResult;
    }
    return RR_OK;
}


