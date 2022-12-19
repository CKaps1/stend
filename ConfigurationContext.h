#include <drogon/plugins/Plugin.h>


#define conf drogon::app().getPlugin<ConfigurationContext>()
namespace stend
{
	class ConfigurationContext : public drogon::Plugin<ConfigurationContext>
	{
	public: 
		size_t USERNAME_MAX = 64, USERNAME_MIN = 5, PASSWORD_MAX = 64, PASSWORD_MIN = 8, EMAIL_MAX = 64, EMAIL_MIN = 1;
		size_t PASSWORD_HASH = 64, REFRESH_TOKEN = 64, ID_TOKEN=128, REFRESH_TOKEN_HASH = 64;
		uint32_t SESSION_LIFETIME = 3600;
		size_t FILENAME = 8;
		size_t COMMENT_MAX = 2048, COMMENT_MIN = 1;
		size_t READ_CACHE = 64 * 1024 * 1024, WRITE_CACHE = READ_CACHE;
		void initAndStart(const Json::Value& config) override;
		void shutdown() override;
	};
	
};