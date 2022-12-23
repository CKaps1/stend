#pragma once
#include "async_mutex.h"
#include "SessionContext.h"
#include "binary.h"
#include <vector>
#include <map>
#include <chrono>
#include <deque>
#include <atomic>
#include <drogon/plugins/Plugin.h>

#define cache drogon::app().getPlugin<SessionCache>()

namespace stend
{	
	
	class StendSession
	{
	private:
		binary idToken_;
		int64_t sessionId_, userId_;
		trantor::Date expiry_;
		std::shared_ptr<SessionContext> context_;
		bool isValid_;
		friend class SessionCache;
	public:
		StendSession(binary idToken, int64_t sessionId, int64_t userId, trantor::Date expiry);
		binary& idToken();
		int64_t sessionId();
		int64_t userId();
		bool isValid();
		std::shared_ptr<SessionContext> context();
		
	};
	class StendSessionPtr : public std::shared_ptr<StendSession>
	{
	public:
		StendSessionPtr(StendSession*);
		StendSessionPtr();
		bool operator==(int64_t value);
	};
	class SessionCache;
	
	class SessionCache : public drogon::Plugin<SessionCache>
	{
	private:
		async_mutex m;

		std::deque<StendSessionPtr> byExpiry;
		std::map<binary, StendSessionPtr> byIdToken;
		std::map<int64_t, StendSessionPtr> bySessionId;
		std::map<int64_t, std::map<int64_t, StendSessionPtr>> byUserId;

		std::function<void(const StendSessionPtr& session)> __insert;
		std::function<void(int64_t sessionId)> __deleteBySessionId;
		std::function<void(int64_t userId)> __deleteByUserId;
		std::function<void(const StendSessionPtr& session)> __update;
		std::function<StendSessionPtr(const binary& idToken)> __getByIdToken;
		void __deleteExpired();
		
	public:
		void initAndStart(const Json::Value& config) override;
		void shutdown() override;
		SessionCache();
		~SessionCache();
		drogon::Task<void> insert(const StendSessionPtr& session); 
		drogon::Task<void> update(const StendSessionPtr& session);
		drogon::Task<void> deleteBySessionId(int64_t sessionId);
		drogon::Task<void> deleteByUserId(int64_t userId);
		drogon::Task<StendSessionPtr> getByIdToken(const binary& idToken);
	};
}