#pragma once
#include "binary.h"
#include "Content.h"
#include "handlers.h"
#include <memory>
#include <shared_mutex>
#include <fstream>

#define FILE_TYPE_NONE 0
#define FILE_TYPE_AUDIO 1
#define FILE_TYPE_VIDEO 2
#define FILE_TYPE_PICTURE 3

namespace stend
{
	enum class SocketOperation
	{
		none = 0, read, write, finalize
	};
	
	class SocketContext
	{
	public:
		SocketContext(SocketOperation _op);
		~SocketContext();
		SocketOperation op = SocketOperation::none;
		std::shared_ptr<FILE> file;
		
	};

	class WriteSocketContext: public SocketContext
	{
	public:
		WriteSocketContext();
		~WriteSocketContext();

		bool unlink_on_close = true;
		drogon_model::stend::Content content;
		std::vector<PermissionInfo> acl_list;
		std::string filename;
		int format;
	};
	typedef std::shared_ptr<SocketContext> SocketContextPtr;
	typedef std::shared_ptr<WriteSocketContext> WriteSocketContextPtr;
}