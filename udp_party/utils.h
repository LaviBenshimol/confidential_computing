#ifndef UTILS_H
#define UTILS_H

#include "types.h"


#ifndef WIN
#define sprintf_s snprintf
#define memcpy_s(dest, destSize, source, count) memcpy(dest, source, count)
#define strnlen_s strnlen
#define SecureZeroMemory explicit_bzero
#endif // #ifndef WIN


class Utils
{
public:
	static void* allocateBuffer(size_t size);
	static void freeBuffer(void* buffer);
	
	static void secureCleanMemory(BYTE* buffer, size_t bufferSize);

	static bool generateRandom(BYTE* buffer, size_t bufferSize);

	static ByteSmartPtr readBufferFromFile(const char* filename);

	//static bool writeBufferToFile(const char* filename, const BYTE* buffer, size_t bufferSize);

	//static void printBuffer(BYTE* buffer, size_t bufferSize);

private:
	static bool get8BytesRandom(unsigned long long* randomResult64);
};



#endif //#ifndef UTILS_H
