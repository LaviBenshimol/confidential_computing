#ifndef SESSION_INTERNALS_H
#define SESSION_INTERNALS_H

class MessageHeader
{
public:
    unsigned int sessionId;
    unsigned int messageCounter;
    unsigned int messageType;
    unsigned int payloadSize;
};


#endif // #ifndef SESSION_INTERNALS_H
