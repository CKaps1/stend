#include "FileDesc.h"
#include <unistd.h>
#include "co.h"

using namespace std;
using namespace stend;

FileDesc::FileDesc() : refcount(new atomic_uint(1))
{
}

FileDesc::FileDesc(int fd_) : fd(co(fd_)), refcount(new atomic_uint(1))
{
}

FileDesc::FileDesc(const FileDesc& obj) 
{
	this->fd = obj.fd;
	this->refcount = obj.refcount;
	if (-1 != obj.fd)
	{
		*this->refcount++;
	}
}

void FileDesc::operator=(const FileDesc& obj)
{
	this->fd = obj.fd;
	this->refcount = obj.refcount;
	if (-1 != obj.fd)
	{
		*this->refcount++;
	}
}

FileDesc::FileDesc(FileDesc&& obj)
{
	this->fd = obj.fd;
	this->refcount = obj.refcount;
	obj.fd = -1;
	obj.refcount = nullptr;
}

void FileDesc::operator=(FileDesc&& obj)
{
	this->fd = obj.fd;
	this->refcount = obj.refcount;
	obj.fd = -1;
	obj.refcount = nullptr;
}

FileDesc::~FileDesc()
{
	if (refcount)
	{
		*refcount--;
		if (refcount == 0)
		{
			delete refcount;
			if (-1 != fd)
			{
				::close(fd);
				fd = -1;
			}
		}
	}
}

void FileDesc::operator=(int fd_)
{
	fd = co(fd_);
}

FileDesc::operator int& ()
{
	return fd;
}

stend::FileDesc::operator bool()
{
	return fd >= 0;
}

bool FileDesc::operator==(const FileDesc& other)
{
	return this->fd == other.fd;
}

bool FileDesc::operator==(int other)
{
	return this->fd == other;
}

bool FileDesc::operator<(const FileDesc& other)
{
	return this->fd < other.fd;
}

bool FileDesc::operator<(int other)
{
	return this->fd < other;
}

void stend::exact_write(int fd, void* buf, size_t sz)
{
	if (sz != write(fd, buf, sz)) throw runtime_error("fd write error");
}

void stend::exact_read(int fd, void* buf, size_t sz)
{
	if (sz != read(fd, buf, sz)) throw runtime_error("fd write error");

}
