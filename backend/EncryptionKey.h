#pragma once
#include <sys/types.h>
#include <cstdint>
#include <string>
#include <memory>
#include "secure_string.h"

namespace stend
{

	class EncryptionKey
	{
	private:
		uint8_t* key = 0;
		size_t size;
	public:
		EncryptionKey(size_t sz);
		~EncryptionKey();
		operator uint8_t* ();
		operator char* ();
		operator void* ();
		operator secure_string();
		size_t Size();
	};
	typedef std::shared_ptr<EncryptionKey> EncryptionKeyPtr;
}

#define INDEX_EMAIL 0
#define INDEX_EMAILSEARCHABLE 1

#define CONTEXT_EMAIL 0x7d03f70ce8ffb8bd
#define CONTEXT_EMAILSEARCHABLE 0x1f79e4643ac42df0 
