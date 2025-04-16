#ifndef TYPES_H
#define TYPES_H

#include <assert.h>

typedef unsigned char BYTE;


class ReferenceCounter
{
private:
    unsigned int count; // Reference count

public:
    void AddRef()
    {
        count++;
    }

    int Release()
    {
        return --count;
    }
};


class ByteSmartPtr
{
public:
    
    ByteSmartPtr(BYTE* pData, size_t size) : _pData(pData), _size(size), _pReferenceCounter(NULL)
    {
        _pReferenceCounter = new ReferenceCounter();
        _pReferenceCounter->AddRef();
    }

    ByteSmartPtr(const ByteSmartPtr& ByteSmartPtr) : _pData(ByteSmartPtr._pData), _size(ByteSmartPtr._size), _pReferenceCounter(ByteSmartPtr._pReferenceCounter)
    {
        _pReferenceCounter->AddRef();
    }

    ByteSmartPtr(BYTE* pData) : _pData(pData), _size(0), _pReferenceCounter(NULL)
    {
        assert(pData == NULL);
        _pReferenceCounter = new ReferenceCounter();
        _pReferenceCounter->AddRef();
    }

    ~ByteSmartPtr();

    operator BYTE* ()
    {
        return _pData;
    }

    BYTE* operator-> ()
    {
        return _pData;
    }

    ByteSmartPtr& operator = (const ByteSmartPtr& ByteSmartPtr);

    size_t size()
    {
        return _size;
    }

private:
    BYTE* _pData;
    size_t _size;
    ReferenceCounter* _pReferenceCounter;
};


#endif // #ifndef TYPES_H
