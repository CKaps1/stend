#pragma once
#include "binary.h"
#include "EncryptionKey.h"
#include <drogon/plugins/Plugin.h>
#include <map>

#define enctx drogon::app().getPlugin<EncryptionContext>()

namespace stend
{
	class EncryptionContext : public drogon::Plugin<EncryptionContext>
	{
	private: std::map <int32_t,EncryptionKeyPtr> keys;
	public:
		void initAndStart(const Json::Value& config) override;
		void shutdown() override;
		binary EncryptSearchable(int64_t ctx, std::string msg, int id);
		binary EncryptSearchable(int64_t ctx, binary msg, int id);
		binary Encrypt(int64_t index, int64_t ctx, std::string msg, binary& nonce, int id);
		binary Encrypt(int64_t index, int64_t ctx, binary msg, binary& nonce, int id);
		binary DecryptBin(int64_t index, int64_t ctx, binary crypto, binary& nonce, int id);
		std::string DecryptStr(int64_t index, int64_t ctx, binary crypto, binary& nonce, int id);
		static binary Hash(binary msg, size_t hashsize, binary salt);
		static binary Hash(std::string msg, size_t hashsize, binary salt);
		static binary RandomNonce();
		static binary RandomSalt();
		static binary Random(size_t sz);
		static int64_t Random64();
	};
}

