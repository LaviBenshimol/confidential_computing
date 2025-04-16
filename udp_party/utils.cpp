#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <immintrin.h>
#include "utils.h"
#ifdef WIN
#include <Windows.h>
#endif // #ifdef WIN


void Utils::secureCleanMemory(BYTE* buffer, size_t bufferSize)
{
	SecureZeroMemory(buffer, bufferSize);
}


/*
void Utils::printBuffer(BYTE* buffer, size_t bufferSize)
{
    for (unsigned int i = 0; i < bufferSize; i++)
    {
        if (i % 16 == 0)
        {
            printf("\n");
        }
        printf("0x%x ", buffer[i]);
    }
    printf("\n");
}
*/

static constexpr unsigned int RANDOM_QUERRY_RETRIES = 20;


bool Utils::get8BytesRandom(unsigned long long* randomResult64)
{
    unsigned int numOfTries = RANDOM_QUERRY_RETRIES;
    int rc = 0;
    do
    {
        numOfTries--;
        rc = _rdrand64_step(randomResult64);
        //rc = _rdseed64_step(randomResult64);
    } while (rc != 1 && numOfTries > 0);

    if (rc == 1)
    {
        return true;
    }
    else
    {
        printf("Error generating random material!\n");
        return false;
    }
}


bool Utils::generateRandom(BYTE* buffer, size_t bufferSize)
{
    unsigned long long randomResult64 = 0ULL;
    size_t leftoversSize = bufferSize % 8;
    size_t roundBufferSize = bufferSize - leftoversSize;
    long long* bufferPart = (long long*)buffer;

    for (unsigned int i = 0; i < roundBufferSize / 8; i++)
    {
        if (get8BytesRandom(&randomResult64))
        {
            *bufferPart = randomResult64;
            bufferPart++;
        }
        else
        {
            return false;
        }
    }

    if (leftoversSize > 0)
    {
        if (get8BytesRandom(&randomResult64))
        {
            BYTE* leftovers = (buffer + roundBufferSize);
            memcpy(leftovers, (BYTE*)(&randomResult64), leftoversSize);
        }
        else
        {
            return false;
        }
    }

    return true;
}


#ifdef WIN
#pragma warning( push )
#pragma warning(disable:4996)
#endif //#ifdef WIN


ByteSmartPtr Utils::readBufferFromFile(const char* filename)
{
    BYTE* buffer = NULL;
    size_t bufferSize = 0;
    FILE* file = fopen(filename, "r");
    if (file != NULL)
    {
        if (fseek(file, 0, SEEK_END) == 0)
        {
            size_t fileSize = ftell(file);
            if (fileSize == -1)
            {
                (void)fclose(file);
                return NULL;
            }

            buffer = (BYTE*)allocateBuffer(fileSize + 1);
            if (buffer == NULL)
            {
                (void)fclose(file);
                return NULL;
            }

            if (fseek(file, 0, SEEK_SET) != 0)
            {
                freeBuffer(buffer);
                (void)fclose(file);
                return NULL;
            }

            bufferSize = fread(buffer, 1, fileSize, file);
            buffer[bufferSize] = 0;
            bufferSize++;
            if (ferror(file) != 0)
            {
                freeBuffer(buffer);
                fclose(file);
                return NULL;
            }
        }
        (void)fclose(file);
    }
    ByteSmartPtr result(buffer, bufferSize);
    return result;
}

/*
bool Utils::writeBufferToFile(const char* filename, const BYTE* buffer, size_t bufferSize)
{
    FILE* file = fopen(filename, "w");
    if (file != NULL)
    {
        size_t sizeWritten = fwrite(buffer, 1, bufferSize, file);
        if (ferror(file) != 0 || sizeWritten != bufferSize)
        {
            (void)fclose(file);
            return false;
        }
        (void)fclose(file);
    }

    return true;
}
*/


#ifdef WIN
#pragma warning( pop )
#endif //#ifdef WIN


void* Utils::allocateBuffer(size_t size)
{
    return malloc(size);
}


void Utils::freeBuffer(void* buffer)
{
    return free(buffer);
}