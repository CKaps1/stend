#pragma once
#include <atomic>
#include <sys/types.h>

namespace stend
{
	class FileDesc
	{
	private:
		int fd = -1;
		std::atomic_uint* refcount;
	public:
		FileDesc();
		FileDesc(int fd_);
		FileDesc(const FileDesc& obj);
		FileDesc(FileDesc&& obj);
		~FileDesc();

		void operator= (int fd_);
		void operator= (const FileDesc& obj);
		void operator= (FileDesc&& obj);

		operator int& ();
		operator bool();

		bool operator==(const FileDesc& other);
		bool operator==(int other);
		bool operator<(const FileDesc& other);
		bool operator<(int other);
	};
	void exact_write(int fd, void* buf, size_t sz);
	void exact_read(int fd, void* buf, size_t sz);
}