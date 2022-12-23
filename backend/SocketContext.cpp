#include "SocketContext.h"
#include <drogon/drogon.h>
#include <filesystem>
#include <vector>
#include <unistd.h>

using namespace std;
using namespace stend;
using namespace std::filesystem;
using namespace drogon;

inline std::string __absolute(std::string local)
{
	path p = path(app().getUploadPath()) / local;
	return p.string();
}

stend::SocketContext::SocketContext(SocketOperation _op) : op(_op)
{
}

stend::SocketContext::~SocketContext() 
{
}


stend::WriteSocketContext::WriteSocketContext() : SocketContext(SocketOperation::write)
{
}

stend::WriteSocketContext::~WriteSocketContext()
{
	if (unlink_on_close && content.getFilename()) unlink(__absolute(content.getValueOfFilename()).c_str());
}
