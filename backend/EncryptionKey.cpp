#include "EncryptionKey.h"
#include "secure_alloc.h"

using namespace stend;

EncryptionKey::EncryptionKey(size_t sz) : size(sz)
{
	key = reinterpret_cast<uint8_t*>(secure_alloc(sz));
}

EncryptionKey::~EncryptionKey()
{
	secure_free(key);
}

EncryptionKey::operator uint8_t* ()
{
	return key;
}

EncryptionKey::operator char* ()
{
	return reinterpret_cast<char*>(key);
}

EncryptionKey::operator void* ()
{
	return reinterpret_cast<void*>(key);
}

EncryptionKey::operator secure_string()
{
	return secure_string(reinterpret_cast<char*>(key), size);
}

size_t EncryptionKey::Size()
{
	return size;
}
