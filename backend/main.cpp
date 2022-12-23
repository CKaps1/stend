#include <drogon/drogon.h>
#include <memory>
#include <csignal>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <systemd/sd-daemon.h>
#include "FileDesc.h"
#include "handlers.h"

using namespace drogon;
using namespace std;
using namespace stend;

#ifndef _DEBUG
__attribute__((constructor)) void init()
{
    if (prctl(PR_SET_DUMPABLE, 0) < 0) abort();
    struct rlimit lim = { 0 };
    if (setrlimit(RLIMIT_CORE, &lim) < 0) abort();
}
#endif

int main(int argc, char* argv[])
{
    try
    {
        signal(SIGSEGV, [](int x) // Should never happen. Only if there is a bug in the code.
            {
                LOG_FATAL << "Segmentation Fault"; //unsafe
                _Exit(x);
            });

        app().loadConfigFile(argc > 1 ? argv[1]:"/etc/stend/config.json");
        
        RegisterAuthenticationHandlers();
        RegisterCommentTagHandlers();
        RegisterHttpFileUploadHandlers();

        if (sd_watchdog_enabled(0, 0))
        {
            uint64_t usec = 0;
            sd_watchdog_enabled(0, &usec);
            app().getLoop()->runEvery(chrono::microseconds(usec / 2), [] { sd_notify(0, "WATCHDOG=1"); });
        }

        sd_notify(0, "READY=1");
        app().run();

    }
    catch (exception& ex)
    {
        LOG_FATAL << ex.what();
        return EXIT_FAILURE;
    }
	return EXIT_SUCCESS;
}