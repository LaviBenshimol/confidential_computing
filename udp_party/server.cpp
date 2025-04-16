#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <csignal>
#include "server_session.h"
#include "server.h"
#include "eliza.h"
#include "utils.h"


static constexpr size_t MAX_MESSAGE_LENGTH = 100;
static constexpr unsigned int TIMEOUT_SEC = 2;


std::map<unsigned int, Eliza*> activeElizaSessions;
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




int playServerSession(unsigned int localPort, const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    running = true;
    BYTE messageBuffer[Session::MESSAGE_BUFFER_SIZE_BYTES];
    memset(messageBuffer, '\0', Session::MESSAGE_BUFFER_SIZE_BYTES);

    ServerSession* listenSession = new ServerSession(localPort, keyFilename, password, certFilename, rootCaFilename, peerIdentity);
    if (!listenSession->active())
    {
        return false;
    }

#ifdef WIN
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)consoleHandler, TRUE);
#else // #ifdef WIN
    signal (SIGINT, consoleHandler);
#endif // #ifdef WIN    

    printf("Server: Starting listening...\n");
    while (listenSession->active() && running)
    {
        BYTE* message = NULL;
        size_t messageSize = 0;
        ServerSession* pChildSession = NULL;
        unsigned int childSessionId = 0;
        
        Session::ReceiveResult rcvResult = listenSession->receiveMessage(messageBuffer, Session::MESSAGE_BUFFER_SIZE_BYTES, TIMEOUT_SEC, &message, &messageSize, &pChildSession, &childSessionId);
        if (rcvResult == Session::RR_DATA_MESSAGE)
        {
            if (message != NULL)
            {
                // find the Eliza session
                std::map<unsigned int, Eliza*>::iterator it = activeElizaSessions.find(childSessionId);
                if (it == activeElizaSessions.end())
                {
                    printf("Message received for invalid session!\n");
                    continue;
                }

                size_t messageLength = strnlen_s((char*)message, MAX_MESSAGE_LENGTH);
                if (messageLength > 0 && messageLength < MAX_MESSAGE_LENGTH)
                {
                    Eliza* eliza = it->second;
                    printf("(%d) Request: \"%s\"\n", childSessionId, (char*)message);
                    bool finishSession = false;
                    std::string response = eliza->getResponse((char*)message, finishSession);
                    if (finishSession)
                    {
                        printf("(%d) Closing.\n", childSessionId);
                        delete eliza;
                        activeElizaSessions.erase(it);
                        listenSession->closeChildSession(childSessionId);
                    }
                    else
                    {
                        printf("(%d) Response: \"%s\"\n", childSessionId, response.c_str());
                        if (!pChildSession->sendDataMessage((const BYTE*)response.c_str(), response.length() + 1))
                        {
                            printf("Error sending a message!");
                            delete listenSession;
                            return false;
                        }
                    }
                }
            }
        }
        else if (rcvResult == Session::RR_NEW_SESSION_CREATED)
        {
            Eliza* eliza = new Eliza();
            activeElizaSessions.insert(std::pair<unsigned int, Eliza*>(childSessionId, eliza));
            printf("(%d) Created\n", childSessionId);
            
            std::string welcomeMessage = eliza->start();
            printf("(%d) Welcome: \"%s\"\n", childSessionId, welcomeMessage.c_str());
            if (!pChildSession->sendDataMessage((const BYTE*)welcomeMessage.c_str(), welcomeMessage.length() + 1))
            {
                printf("Error sending a message!");
                delete listenSession;
                return false;
            }
        }
        else if (rcvResult == Session::RR_SESSION_CLOSED)
        {
            std::map<unsigned int, Eliza*>::iterator it = activeElizaSessions.find(childSessionId);
            if (it == activeElizaSessions.end())
            {
                printf("Close session received for invalid session!\n");
                continue;
            }

            Eliza* eliza = it->second;
            delete eliza;
            activeElizaSessions.erase(it);
            printf("(%d) Closed\n", childSessionId);
        }
        else if (rcvResult == Session::RR_FATAL_ERROR)
        {
            printf("Error during receiving a message! Closing all");
            delete listenSession;
            return false;
        }
    }
    
    printf("Server: terminated!\n");
    delete listenSession;
    return true;
}