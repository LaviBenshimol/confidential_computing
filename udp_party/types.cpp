#include <stdlib.h>
#include "types.h"
#include "utils.h"



ByteSmartPtr::~ByteSmartPtr()
{
    if (_pReferenceCounter->Release() == 0)
    {
        Utils::secureCleanMemory(_pData, _size);
        Utils::freeBuffer(_pData);
        delete _pReferenceCounter;
    }
}


ByteSmartPtr& ByteSmartPtr::operator = (const ByteSmartPtr& ByteSmartPtr)
{
    if (this != &ByteSmartPtr)
    {
        if (_pReferenceCounter->Release() == 0)
        {
            Utils::secureCleanMemory(_pData, _size);
            Utils::freeBuffer(_pData);
            delete _pReferenceCounter;
        }

        _pData = ByteSmartPtr._pData;
        _size = ByteSmartPtr._size;
        _pReferenceCounter = ByteSmartPtr._pReferenceCounter;
        _pReferenceCounter->AddRef();
    }
    return *this;
}