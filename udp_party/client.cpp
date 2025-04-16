#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <csignal>
#include <iostream>
#include "client_session.h"
#include "client.h"
#include "utils.h"


static constexpr size_t MAX_MESSAGE_LENGTH = 100;
static constexpr unsigned int TIMEOUT_SEC = 2;

static bool running = true;


#ifdef WIN
    static bool consoleHandler(int signal) 
    {
        if (signal == CTRL_C_EVENT) 
        {
            running = false;
        }
        return true;
    }
#else // #ifdef WIN
    static void consoleHandler(int signal) 
    {
        if (signal == SIGINT) 
        {
            running = false;
        }
    }
#endif // #ifdef WIN


void readLine(char* instr) {
    char c;
    int slen = 0;

    c = getchar();
    while (c != '\n')
    {
        instr[slen++] = c;
        if (slen == MAX_MESSAGE_LENGTH)
        {
            break;
        }
        c = getchar();
    }
    instr[slen] = '\0';
}


bool playClientSession(const char* remoteIpAddress, unsigned int remotePort, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    running = true;
    BYTE messageBuffer[Session::MESSAGE_BUFFER_SIZE_BYTES];
    memset(messageBuffer, '\0', Session::MESSAGE_BUFFER_SIZE_BYTES);

#ifdef WIN
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)consoleHandler, TRUE);
#else // #ifdef WIN
    signal (SIGINT, consoleHandler);
#endif // #ifdef WIN

    ClientSession* session = new ClientSession(remotePort, remoteIpAddress, keyFilename, password, certFilename, rootCaFilename, peerIdentity);
    if (!session->active())
    {
        delete session;
        return false;
    }

    while (running)
    {
        BYTE* message = NULL;
        size_t messageSize = 0;
        Session::ReceiveResult rcvResult = session->receiveMessage(messageBuffer, Session::MESSAGE_BUFFER_SIZE_BYTES, TIMEOUT_SEC, &message, &messageSize);
        if (rcvResult == Session::RR_DATA_MESSAGE)
        {
            if (message != NULL)
            {
                printf("Received response:");
                size_t messageLength = strnlen_s((char*)message, MAX_MESSAGE_LENGTH);
                if (messageLength > 0 && messageLength < MAX_MESSAGE_LENGTH)
                {
                    printf("\"%s\"\n", message);
                }
                else
                {
                    printf("BAD MESSAGE!\n");
                }
            }
        }
        else if (rcvResult == Session::RR_SESSION_CLOSED)
        {
            printf("Session ended by remote party.\n");
            running = false;
        }
        else
        {
            printf("Receive error!");
            delete session;
            return false;
        }

        if (running)
        {
            readLine((char*)messageBuffer);
            if (!session->sendDataMessage((const BYTE*)messageBuffer, strnlen_s((char*)messageBuffer, MAX_MESSAGE_LENGTH) + 1))
            {
                delete session;
                return false;
            }
        }
    }
    
    delete session;
    return true;
}