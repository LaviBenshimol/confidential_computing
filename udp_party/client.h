#ifndef CLIENT_H
#define CLIENT_H


bool playClientSession(const char* remoteIpAddress, unsigned int remotePort, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity);


#endif // #ifndef CLIENT_H
