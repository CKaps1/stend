#include "SessionCache.h"
#include "co.h"
#include <drogon/drogon.h>

using namespace stend;
using namespace std;
using namespace drogon;
using namespace trantor;
using namespace std::chrono;

stend::StendSession::StendSession(binary idToken, int64_t sessionId, int64_t userId, trantor::Date expiry)
	:idToken_(idToken), sessionId_(sessionId), userId_(userId), expiry_(expiry), context_(new SessionContext()), isValid_(true)
{
}

binary& stend::StendSession::idToken()
{
	return idToken_;
}

int64_t stend::StendSession::sessionId()
{
	return sessionId_;
}

int64_t stend::StendSession::userId()
{
	return userId_;
}

bool stend::StendSession::isValid()
{
	return isValid_ && trantor::Date::now() < expiry_;
}

std::shared_ptr<SessionContext> stend::StendSession::context()
{
	return context_;
}

stend::StendSessionPtr::StendSessionPtr(StendSession* session) : shared_ptr<StendSession>(session)
{
}

stend::StendSessionPtr::StendSessionPtr()
{
}

bool stend::StendSessionPtr::operator==(int64_t value)
{
	return this->get()->sessionId() == value;
}


stend::SessionCache::SessionCache() 
{
	app().getLoop()->runEvery(2min, [this]
		{
			this->__deleteExpired();
		});

	__insert = [this](const StendSessionPtr& session)
	{
		this->byExpiry.push_back(session);
		this->byIdToken.insert(make_pair(session->idToken(), session));
		this->bySessionId.insert(make_pair(session->sessionId(), session));
		this->byUserId[session->userId()].insert(make_pair(session->sessionId(), session));
	};

	__deleteBySessionId = [this](int64_t sessionId)
	{
		StendSessionPtr ptr = this->bySessionId.at(sessionId);
		this->byExpiry.erase(find(byExpiry.begin(), byExpiry.end(), sessionId));
		this->bySessionId.erase(sessionId);
		this->byIdToken.erase(ptr->idToken());
		auto& u = this->byUserId[ptr->userId()];
		u.erase(sessionId);
		if (u.empty()) this->byUserId.erase(ptr->userId());
	};

	__deleteByUserId = [this](int64_t userId)
	{
		auto& u = this->byUserId.at(userId);
		for (auto& val : u)
		{
			this->byExpiry.erase(find(byExpiry.begin(), byExpiry.end(), val.second->sessionId()));
			this->bySessionId.erase(val.second->sessionId());
			this->byIdToken.erase(val.second->idToken());
		}
		byUserId.erase(userId);
	};

	__update = [this](const StendSessionPtr& session)
	{
		std::find(this->byExpiry.begin(), this->byExpiry.end(), session)->get()->context_ = session->context();

		auto& old = this->byIdToken[session->idToken()];
		old->context_ = session->context();

		bySessionId[old->sessionId()]->context_ = session->context();

		byUserId[old->userId()][old->sessionId()]->context_ = session->context();
	};

	__getByIdToken = [this](const binary& idToken)->StendSessionPtr
	{
		auto& res = byIdToken.at(idToken);
		cb(res->isValid());
		return res;
	};
}

void stend::SessionCache::__deleteExpired()
{
	while (!byExpiry.empty())
	{
		auto ptr = byExpiry.front();
		if (!ptr->isValid())
		{
			this->bySessionId.erase(ptr->sessionId());
			this->byIdToken.erase(ptr->idToken());
			auto& u = this->byUserId[ptr->userId()];
			u.erase(ptr->sessionId());
			if (u.empty()) this->byUserId.erase(ptr->userId());
			byExpiry.pop_front();
		}
		else return;
	}
}

stend::SessionCache::~SessionCache()
{
}

drogon::Task<void> stend::SessionCache::insert(const StendSessionPtr& session)
{
	auto lck = co_await m.scoped_lock_async();
	__insert(session);
	co_return;
}

drogon::Task<void> stend::SessionCache::update(const StendSessionPtr& session)
{
	auto lck = co_await m.scoped_lock_async();
	__update(session);
	co_return;
}

drogon::Task<void> stend::SessionCache::deleteBySessionId(int64_t sessionId)
{
	auto lck = co_await m.scoped_lock_async();
	__deleteBySessionId(sessionId);
	co_return;
}

drogon::Task<void> stend::SessionCache::deleteByUserId(int64_t userId)
{
	auto lck = co_await m.scoped_lock_async();
	__deleteByUserId(userId);
	co_return;
}

drogon::Task<StendSessionPtr> stend::SessionCache::getByIdToken(const binary& idToken)
{
	auto lck = co_await m.scoped_lock_async();
	co_return __getByIdToken(idToken);
}

void stend::SessionCache::initAndStart(const Json::Value& config)
{
}

void stend::SessionCache::shutdown()
{
}
