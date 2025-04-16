#ifndef SERVER_H
#define SERVER_H


int playServerSession(unsigned int localPort, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity);


#endif // #ifndef SERVER_H
