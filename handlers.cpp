#include "handlers.h"
#include "co.h"
#include "SocketContext.h"
#include "Users.h"
#include "Sessions.h"
#include "Tagassociations.h"
#include "Tags.h"
#include "Acl.h"
#include "Votes.h"
#include "Comments.h"
#include "transaction.h"
#include "EncryptionContext.h"
#include "ConfigurationContext.h"
#include <cmath>
#include <filesystem>
#include <cstdio>

using namespace stend;
using namespace drogon;
using namespace std;
using namespace Json;
using namespace drogon::orm;
using namespace drogon_model::stend;
using namespace std::filesystem;

std::shared_ptr<Json::Value> stend::_getJson(const drogon::HttpRequestPtr& request)
{
	auto& value = request->jsonObject();
	cb((bool)value);
	return value;
}

void stend::__checkJson(const std::shared_ptr<Json::Value> val, std::string name)
{
	cb(val->isMember(name));
}

string GetTypeString(string ext)
{
	if (ext == "webm")
		return "video/webm";
	else if (ext == "ogg")
		return "audio/ogg";
	else if (ext == "jpeg")
		return "image/jpeg";
	else
		throw runtime_error("invalid format");
}

short ValidPermission(short perm)
{
	switch (perm)
	{
	case PERMISSION_DENY:
	case PERMISSION_NONE:
	case PERMISSION_VIEW:
		return perm;
	default:
		throw runtime_error("invalid permission");
	}
}

inline drogon::Task<StendSessionPtr> stend::__getByIdToken(binary idToken)
{
	co_return co_await cache->getByIdToken(idToken);
}

drogon::Task<int64_t> stend::__userIdFromUsername(std::string username)
{
	CoroMapper<Users> user_mapper(app().getFastDbClient());
	Users user = co_await user_mapper.findOne(Criteria(Users::Cols::_userid, username));
	co_return user.getValueOfUserid();
}

drogon::Task<drogon_model::stend::Users> stend::userInfo(int64_t userId)
{
	CoroMapper<Users> mapper(app().getFastDbClient());
	co_return co_await mapper.findByPrimaryKey(userId);
}

drogon::Task<> stend::__deleteFile(int64_t fileId, transptr trans) // postgresql trigger to delete filesystem file
{
	CoroMapper<Comments> comment_mapper(trans);
	for (auto comment : co_await comment_mapper.findBy(Criteria(Comments::Cols::_contentid, fileId)))
		co_await __deleteComment(comment.getValueOfCommentid(), trans);
	co_await __deletePermissions(fileId, trans);
	co_await __removeAllTags(fileId, trans);
}

std::string stend::RandomFilename(int format)
{
	string extension;
	switch (format)
	{
	case FILE_TYPE_AUDIO:
		extension = "ogg";
		break;
	case FILE_TYPE_PICTURE:
		extension = "jpeg";
	case FILE_TYPE_VIDEO:
		extension = "webm";
		break;
	default:
		throw runtime_error("invalid format");
	}

	string bin = EncryptionContext::Random(conf->FILENAME);
	return bin + "." + extension;
}

std::string stend::absolute(std::string local)
{
	path _prefix(app().getUploadPath());
	return (_prefix / local).string();
}

drogon::Task<bool> stend::__HasUserPermission(int64_t userId, int64_t contentId, short permission)
{
	CoroMapper<Acl> mapper(app().getFastDbClient());

	auto acl = co_await mapper.findOne(Criteria(Acl::Cols::_owner, userId) && Criteria(Acl::Cols::_contentid, contentId));
	co_return acl.getValueOfPermission() == permission;
}

drogon::Task<> stend::__deletePermissions(int64_t contentId, std::shared_ptr<drogon::orm::Transaction> trans)
{
	CoroMapper<Acl> mapper(trans);
	co_await mapper.deleteBy(Criteria(Acl::Cols::_contentid, contentId));
	co_return;
}

drogon::Task<> stend::SetPermission(int64_t idOwner, PermissionInfo perm)
{
	transaction
	{
		/*CoroMapper<Acl> mapper(trans);

		int count = co_await mapper.count(Criteria(Acl::Cols::_contentid, perm.contentId));

		if (perm.permission == PERMISSION_NONE)
		{
			if (count) co_await mapper.deleteBy(Criteria(Acl::Cols::_contentid, perm.contentId) && Criteria(Acl::Cols::_owner, idOwner));
		}
		else
		{
			if (count)
				co_await mapper.updateBy({ Acl::Cols::_permission }, Criteria(Acl::Cols::_contentid, perm.contentId) &&
					Criteria(Acl::Cols::_owner, idOwner), perm.permission);
			else
			{
				Acl acl;
				acl.setContentid(perm.contentId);
				acl.setOwner(idOwner);
				acl.setPermission(perm.contentId);
				co_await mapper.insert(acl);
			}
		}*/
		co_return;
	}commit;
}

drogon::Task<PermissionInfo> stend::GetPermission(binary idTokenOwner, int64_t contentId, int64_t userId)
{
	transaction
	{
		CoroMapper<Acl> mapper(trans);

		auto session = co_await __getByIdToken(idTokenOwner);
		Acl acl = co_await mapper.findOne(Criteria(Acl::Cols::_userid, session->userId()) && Criteria(Acl::Cols::_contentid, contentId));
		co_return PermissionInfo
		{
			.contentId = acl.getValueOfContentid(),
			.userId = userId,
			.permission = acl.getValueOfPermission(),
		};
	}commit;
}

// note: drogon handles exceptions, logs them, and possibly responds to them (have to test). don't need to worry about them.
void stend::RegisterAuthenticationHandlers()
{
	app().registerHandler("/api/user/register", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(username); paramStr(email); paramStr(password);
			co_await CreateUser(username, email, password);
			callback(HttpResponse::newHttpResponse());
			co_return;

		}, { Put });
	app().registerHandler("/api/user/login", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson; paramStr(usernameOrEmail); paramStr(password);
			LoginInfo info;

			if (usernameOrEmail.find('@') != string::npos)  info = co_await LoginByEmail(usernameOrEmail, password);
			else  info = co_await LoginByUsername(usernameOrEmail, password);
			Value res;
			res["idToken"] = info.idToken;
			res["refreshToken"] = info.refreshToken;
			res["sessionId"] = (Int64)info.SessionID;
			res["expiry"] = (Int64)info.expiry.secondsSinceEpoch();
			callback(HttpResponse::newHttpJsonResponse(res));
			co_return;
		}, { Post });

	app().registerHandler("/api/user/logout", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson; paramStr(refreshToken); paramInt64(sessionId);
			co_await Logout((refreshToken),(sessionId));
			callback(HttpResponse::newHttpResponse());
			co_return;
		}, { Post });
	app().registerHandler("/api/user/token", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson; paramStr(idToken); paramInt64(sessionId);
			auto info = co_await Refresh(idToken, sessionId);
			callback(HttpResponse::newHttpResponse());
			Value res;
			res["idToken"] = info.idToken;
			res["refreshToken"] = info.refreshToken;
			res["sessionId"] = (Int64)info.SessionID;
			res["expiry"] = (Int64)info.expiry.secondsSinceEpoch();
			callback(HttpResponse::newHttpJsonResponse(res));
		}, { Post });
	app().registerHandler("/api/user/logoutAll", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson; paramStr(refreshToken); paramInt64(sessionId);
			co_await LogoutAll((refreshToken), (sessionId));
			callback(HttpResponse::newHttpResponse());
			co_return;
		}, { Post });
	app().registerHandler("/api/user/deleteAccount", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson; paramStr(idToken);
			StendSessionPtr session = co_await __getByIdToken(idToken);
			co_await __DeleteAccount(session->userId());
			callback(HttpResponse::newHttpResponse());
			co_return;
		}, { Delete });
}

drogon::Task<> stend::CreateUser(std::string username, std::string email, std::string password)
{
	transaction
	{
		CoroMapper<Users> user_mapper(trans);

		cb(conf->USERNAME_MIN < username.length() < conf->USERNAME_MAX);
		cb(conf->PASSWORD_MIN < password.length() < conf->PASSWORD_MAX);
		cb(conf->EMAIL_MIN < email.length() < conf->EMAIL_MAX);

		binary salt = EncryptionContext::RandomSalt(), emailnonce = EncryptionContext::RandomNonce(); // temporarily null - user id needed

		Users usr;
		usr.setEmail(EncryptionContext::RandomSalt());
		usr.setEmailnonce(emailnonce);
		usr.setEmailsearchable(enctx->EncryptSearchable(CONTEXT_EMAILSEARCHABLE, email, INDEX_EMAILSEARCHABLE)); // auto accounts for email differences. Query would fail...
		usr.setUsername(username);
		usr.setPasswordhash(EncryptionContext::Hash(password, conf->PASSWORD_HASH, salt));
		usr.setPasswordsalt(salt);

		Users res = co_await user_mapper.insert(usr);

		res.setEmail(enctx->Encrypt(usr.getValueOfUserid(), CONTEXT_EMAIL, email, emailnonce, INDEX_EMAIL));
		res.setEmailnonce(emailnonce);

		co_await user_mapper.update(res);
		co_return;
	}commit;
}

drogon::Task<LoginInfo> stend::LoginByUsername(std::string username, std::string password)
{
	transaction
	{
		CoroMapper<Users> user_mapper(trans);
		CoroMapper<Sessions> session_mapper(trans);

		cb(conf->USERNAME_MIN < username.length() < conf->USERNAME_MAX);
		cb(conf->PASSWORD_MIN < password.length() < conf->PASSWORD_MAX);

		trantor::Date now = trantor::Date::now();
		Users usr = co_await user_mapper.findOne(Criteria(Users::Cols::_username, username));

		if (usr.getIncorrectPasswordAttempts())
		{
			if (usr.getValueOfIncorrectPasswordAttemptDate().after(exp(usr.getValueOfIncorrectPasswordAttempts())) > now)
				throw runtime_error("permission denied");
		}

		binary pwhash = EncryptionContext::Hash(password, conf->PASSWORD_HASH, usr.getValueOfPasswordsalt());

		if (sodium_memcmp(pwhash.data(), usr.getValueOfPasswordhash().data(), min<size_t>(pwhash.size(), usr.getValueOfPasswordhash().size())))
		{
			throw runtime_error("permission denied");
		}

		LoginInfo info;
		binary refreshKeySalt = EncryptionContext::RandomSalt();
		info.refreshToken = EncryptionContext::Random(conf->REFRESH_TOKEN);
		info.idToken = EncryptionContext::Random(conf->ID_TOKEN);
		info.expiry = now.after(conf->SESSION_LIFETIME);

		Sessions session;
		session.setUserid(usr.getValueOfUserid());
		session.setRefreshkeysalt(refreshKeySalt);
		session.setRefreshkeyhash(EncryptionContext::Hash(info.refreshToken, conf->REFRESH_TOKEN, refreshKeySalt));
		session.setExpirydate(info.expiry);
		Sessions sessionres = co_await session_mapper.insert(session);
		info.SessionID = sessionres.getValueOfSessionid();

		StendSessionPtr stend_session(new StendSession(info.idToken, info.SessionID, usr.getValueOfUserid(), info.expiry));
		co_await cache->insert(stend_session);

		co_return info;
	}commit;

}

drogon::Task<LoginInfo> stend::LoginByEmail(std::string email, std::string password)
{
	transaction
	{
		CoroMapper<Users> user_mapper(trans);
		CoroMapper<Sessions> session_mapper(trans);
		cb(conf->USERNAME_MIN < password.length() < conf->USERNAME_MAX);
		cb(conf->EMAIL_MIN < email.length() < conf->EMAIL_MAX);

		trantor::Date now = trantor::Date::now();
		string emailSearchable = bin_to_hex(enctx->EncryptSearchable(CONTEXT_EMAILSEARCHABLE, email, INDEX_EMAILSEARCHABLE));
		Users usr = co_await user_mapper.findOne(Criteria(Users::Cols::_emailsearchable, emailSearchable.insert(0, "\\x")));

		if (usr.getIncorrectPasswordAttempts())
		{
			if (usr.getValueOfIncorrectPasswordAttemptDate().after(exp(usr.getValueOfIncorrectPasswordAttempts())) > now)
				throw runtime_error("permission denied");
		}

		binary pwhash = EncryptionContext::Hash(password, conf->PASSWORD_HASH, usr.getValueOfPasswordsalt());

		if (sodium_memcmp(pwhash.data(), usr.getValueOfPasswordhash().data(), min<size_t>(pwhash.size(), usr.getValueOfPasswordhash().size())))
		{
			throw runtime_error("permission denied");
		}

		LoginInfo info;
		binary refreshKeySalt = EncryptionContext::RandomSalt();
		info.refreshToken = EncryptionContext::Random(conf->REFRESH_TOKEN);
		info.idToken = EncryptionContext::Random(conf->ID_TOKEN);
		info.expiry = now.after(conf->SESSION_LIFETIME);

		Sessions session;
		session.setUserid(usr.getValueOfUserid());
		session.setRefreshkeysalt(refreshKeySalt);
		session.setRefreshkeyhash(EncryptionContext::Hash(info.refreshToken, conf->REFRESH_TOKEN, refreshKeySalt));
		session.setExpirydate(info.expiry);
		Sessions sessionres = co_await session_mapper.insert(session);
		info.SessionID = sessionres.getValueOfSessionid();

		StendSessionPtr stend_session(new StendSession(info.idToken, info.SessionID, usr.getValueOfUserid(), info.expiry));
		co_await cache->insert(stend_session);

		co_return info;
	}commit;
}

drogon::Task<LoginInfo> stend::Refresh(binary refreshToken, int64_t SessionId)
{
	transaction
	{
		trantor::Date now = trantor::Date::now();
		CoroMapper<Users> user_mapper(trans);
		CoroMapper<Sessions> session_mapper(trans);
		auto session = co_await session_mapper.findByPrimaryKey(SessionId);

		binary hash1 = session.getValueOfRefreshkeyhash();
		binary salt = session.getValueOfRefreshkeysalt();
		binary hash2 = EncryptionContext::Hash(refreshToken, conf->REFRESH_TOKEN, salt);
		cb(hash1 == hash2);

		LoginInfo info;
		binary refreshKeySalt = EncryptionContext::RandomSalt();
		info.refreshToken = EncryptionContext::Random(conf->REFRESH_TOKEN);
		info.idToken = EncryptionContext::Random(conf->ID_TOKEN);
		info.expiry = now.after(conf->SESSION_LIFETIME);

		Sessions res;
		res.setUserid(session.getValueOfUserid());
		res.setRefreshkeysalt(refreshKeySalt);
		res.setRefreshkeyhash(EncryptionContext::Hash(info.refreshToken, conf->REFRESH_TOKEN_HASH, refreshKeySalt));
		res.setExpirydate(info.expiry);
		Sessions sessionres = co_await session_mapper.insert(res);
		info.SessionID = sessionres.getValueOfSessionid();

		StendSessionPtr stend_session(new StendSession(info.idToken, info.SessionID, session.getValueOfUserid(), info.expiry));
		co_await cache->insert(stend_session);

		co_await session_mapper.deleteByPrimaryKey(SessionId);
		co_return info;
	}commit;
}

drogon::Task<> stend::Logout(binary refreshToken, int64_t SessionId)
{
	transaction
	{
		CoroMapper<Users> user_mapper(trans);
		CoroMapper<Sessions> session_mapper(trans);
		cb(conf->REFRESH_TOKEN == refreshToken.size());

		Sessions session = co_await session_mapper.findByPrimaryKey(SessionId);
		binary hash1 = session.getValueOfRefreshkeyhash();
		binary salt = session.getValueOfRefreshkeysalt();
		binary hash2 = EncryptionContext::Hash(refreshToken, conf->REFRESH_TOKEN, salt);
		cb(hash1 == hash2);

		co_await session_mapper.deleteByPrimaryKey(SessionId);
		co_await cache->deleteBySessionId(SessionId);

		co_return;
	}commit;
}

drogon::Task<> stend::LogoutAll(binary refreshToken, int64_t SessionId)
{
	transaction
	{
		CoroMapper<Users> user_mapper(trans);
		CoroMapper<Sessions> session_mapper(trans);
		Sessions session = co_await session_mapper.findByPrimaryKey(SessionId);
		binary hash1 = session.getValueOfRefreshkeyhash();
		binary salt = session.getValueOfRefreshkeysalt();
		binary hash2 = EncryptionContext::Hash(refreshToken, conf->REFRESH_TOKEN, salt);
		cb(hash1 == hash2);

		co_await session_mapper.deleteBy(Criteria(Sessions::Cols::_userid, session.getValueOfUserid()));
		co_await cache->deleteByUserId(session.getValueOfUserid());

		co_return;
	}commit;
}

drogon::Task<> stend::setTags(int64_t userId, int64_t contentId, std::vector<std::string> tags)
{
	transaction
	{
		CoroMapper<Content> content_mapper(trans);
		CoroMapper<Tags> tag_mapper(trans);
		CoroMapper<Tagassociations> assoc_mapper(trans);
		Content content = co_await content_mapper.findByPrimaryKey(contentId);
		cb(content.getValueOfOwner() == userId);

		for (auto tag : tags)
		{
			int64_t tagid;
			int64_t count = co_await tag_mapper.count(Criteria(Tags::Cols::_name, tag));
			if (count == 0)
			{
				Tags t;
				t.setName(tag);
				Tags res = co_await tag_mapper.insert(t);
				tagid = res.getValueOfTagid();
			}
			else
			{
				Tags res = co_await tag_mapper.findOne(Criteria(Tags::Cols::_name, tag));
				tagid = res.getValueOfTagid();
			}
			Tagassociations ta;
			ta.setTagid(tagid);
			ta.setContentid(content.getValueOfContentid());
			co_await assoc_mapper.insert(ta);
		}

		co_return;
	}commit;
}

drogon::Task<std::vector<std::string>> stend::getTags(int64_t userId, int64_t contentId)
{
	transaction
	{
		CoroMapper<Content> content_mapper(trans);
		CoroMapper<Tags> tag_mapper(trans);
		CoroMapper<Tagassociations> assoc_mapper(trans); Content content = co_await content_mapper.findByPrimaryKey(contentId);

		cb(content.getValueOfOwner() == userId ||
			co_await __HasUserPermission(userId, content.getValueOfContentid(), PERMISSION_VIEW) ||
			(content.getValueOfIspublic() == "1" &&
				!co_await __HasUserPermission(userId, content.getValueOfContentid(), PERMISSION_DENY)));

		std::vector<Tagassociations> va = co_await assoc_mapper.findBy(Criteria(Tagassociations::Cols::_contentid, contentId));
		std::vector<string> res(va.size());
		size_t i = 0;

		for (auto assoc : va)
		{
			auto tag = co_await tag_mapper.findOne(Criteria(Tags::Cols::_tagid, assoc.getValueOfTagid()));
			res[i++] = tag.getValueOfName();
		}

		co_return res;
	}commit;
}

drogon::Task<> stend::removeTags(int64_t userId, int64_t contentId, std::vector<std::string> tags)
{
	transaction
	{
		CoroMapper<Content> content_mapper(trans);
		CoroMapper<Tags> tag_mapper(trans);
		CoroMapper<Tagassociations> assoc_mapper(trans);
		Content content = co_await content_mapper.findByPrimaryKey(contentId);
		cb(content.getValueOfOwner() == userId);

		for (auto tag : tags)
		{
			Tags t = co_await tag_mapper.findOne(Criteria(Tags::Cols::_name, tag));
			co_await assoc_mapper.deleteBy(Criteria(Tagassociations::Cols::_tagid, t.getValueOfTagid()) && Criteria(Tagassociations::Cols::_contentid, content.getValueOfContentid()));
		}
		co_return;
	}commit;
}

drogon::Task<> stend::removeAllTags(int64_t userId, int64_t contentId)
{
	transaction
	{
		CoroMapper<Content> content_mapper(trans);
		Content content = co_await content_mapper.findByPrimaryKey(contentId);
		cb(content.getValueOfOwner() == userId);

		co_await __removeAllTags(contentId, trans);
	}
	commit;
}

drogon::Task<> stend::__removeAllTags(int64_t contentId, transptr trans)
{
	CoroMapper<Tagassociations> mapper(trans);
	co_await mapper.deleteBy(Criteria(Tagassociations::Cols::_contentid, contentId));
	co_return;
}

drogon::Task<> __removeAllTags(int64_t contentId, transptr trans)
{
	CoroMapper<Tagassociations> assoc_mapper(trans);
	co_await assoc_mapper.deleteBy(Criteria(Tagassociations::Cols::_contentid, contentId));
	co_return;
}


drogon::Task<> stend::__DeleteAccount(int64_t userId)
{
	transaction
	{
		CoroMapper<Content> content_mapper(trans);
		CoroMapper<Sessions> session_mapper(trans);
		CoroMapper<Users> user_mapper(trans);

		for (auto content : co_await content_mapper.findBy(Criteria(Content::Cols::_owner, userId)))
			co_await __deleteFile(content.getValueOfContentid(), trans);

		co_await session_mapper.deleteBy(Criteria(Sessions::Cols::_userid, userId));
		co_await user_mapper.deleteBy(Criteria(Users::Cols::_userid, userId));
		co_return;
	}
	commit;
}

void stend::RegisterCommentTagHandlers()
{
	app().registerHandler("/api/comment/addComment", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(contentId);
			paramStr(text);

			Value res;
			auto session = co_await __getByIdToken(idToken);
			res["commentId"] = (Int64)co_await addComment(session->userId(), contentId, text);
			callback(HttpResponse::newHttpJsonResponse(res));
			co_return;
		}, { Post });
	app().registerHandler("/api/comment/getComments", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(contentId);
			paramInt(offset);
			paramInt(count);
			
			Value res;
			auto session = co_await __getByIdToken(idToken);
			for (auto info : co_await getComments(session->userId(), contentId, offset, count))
			{
				Value value;
				value["text"] = info.text;
				value["upvotes"] = info.upvotes;
				value["downvotes"] = info.downvotes;
				value["commentId"] = (Int64)info.commentId;
				
				Value ui;
				auto userinfo = co_await userInfo(info.userId);
				ui["username"] = userinfo.getValueOfUsername();
				ui["displayname"] = userinfo.getValueOfDisplayname();

				value["user"] = ui;
				res.append(value);
			}

			callback(HttpResponse::newHttpJsonResponse(res));
			co_return;
		}, { Get });
	app().registerHandler("/api/comment/getSingleComment", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(contentId);

			auto session = co_await __getByIdToken(idToken);
			auto info = co_await getSingleComment(session->userId(),contentId);
			
			Value res;
			res["text"] = info.text;
			res["upvotes"] = info.upvotes;
			res["downvotes"] = info.downvotes;
			res["commentId"] = (Int64)info.commentId;

			Value ui;
			auto userinfo = co_await userInfo(info.userId);
			ui["username"] = userinfo.getValueOfUsername();
			ui["displayname"] = userinfo.getValueOfDisplayname();

			res["user"] = ui;
			
			callback(HttpResponse::newHttpJsonResponse(res));

			co_return;
		}, { Get });
	app().registerHandler("/api/comment/upvote", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(commentId);

			auto session = co_await __getByIdToken(idToken);
			co_await upvote(session->userId(), commentId);

			callback(HttpResponse::newHttpResponse());
			co_return;

		}, { Post });
	app().registerHandler("/api/comment/downvote", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(commentId);

			auto session = co_await __getByIdToken(idToken);
			co_await downvote(session->userId(), commentId);

			callback(HttpResponse::newHttpResponse());
			co_return;

		}, { Post });
	app().registerHandler("/api/comment/delete", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(commentId);

			auto session = co_await __getByIdToken(idToken);
			co_await deleteComment(session->userId(), commentId);

			callback(HttpResponse::newHttpResponse());
			co_return;

		}, { Delete });
	app().registerHandler("/api/tags/setTags", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(contentId);

			auto session = co_await __getByIdToken(idToken);
			auto t = value->operator[]("tags");

			vector<string> tags(t.size()); size_t i = 0;
			for (auto tag : t) tags[i++] = t.asString();

			co_await setTags(session->userId(), contentId, tags);

			callback(HttpResponse::newHttpResponse());
			co_return;

		}, { Post });
	app().registerHandler("/api/tags/getTags", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(contentId);

			auto session = co_await __getByIdToken(idToken);
			auto tags = co_await getTags(session->userId(), contentId);

			Value res;
			for (auto str : tags)res.append(str);

			callback(HttpResponse::newHttpJsonResponse(res));
			co_return;

		}, { Post });
	app().registerHandler("/api/tags/removeTags", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->Task<>
		{
			GetJson;
			paramStr(idToken);
			paramInt64(contentId);

			auto session = co_await __getByIdToken(idToken);
			auto t = value->operator[]("tags");

			vector<string> tags(t.size()); size_t i = 0;
			for (auto tag : t) tags[i++] = t.asString();

			co_await removeTags(session->userId(), contentId, tags);

			callback(HttpResponse::newHttpResponse());
			co_return;

		}, { Post });
}

drogon::Task<int64_t> stend::addComment(int64_t userId, int64_t contentId, std::string text)
{
	transaction
	{
		CoroMapper<Comments> mapper(trans);
		CoroMapper<Content> content_mapper(trans);

		cb(conf->COMMENT_MIN < text.length() < conf->COMMENT_MAX);

		Comments comment;
		comment.setUserid(userId);
		comment.setContentid(contentId);
		comment.setComment(text);

		Content content = co_await content_mapper.findByPrimaryKey(contentId);
		cb(content.getValueOfIspublic() == "1" || co_await __HasUserPermission(userId, contentId, PERMISSION_VIEW));
		cb(content.getValueOfCancomment() == "1");

		Comments res = co_await mapper.insert(comment);
		co_return res.getValueOfCommentid();
	} commit;
}

drogon::Task<std::vector<CommentInfo>> stend::getComments(int64_t userId, int64_t contentId, size_t offset, size_t count)
{
	transaction
	{
		CoroMapper<Comments> mapper(trans);
		CoroMapper<Content> content_mapper(trans);

		Content content = co_await content_mapper.findByPrimaryKey(contentId);
		cb(content.getValueOfIspublic() == "1" || co_await __HasUserPermission(userId, contentId, PERMISSION_VIEW));

		auto res = co_await trans->execSqlCoro("SELECT commentId, userId, contentId, upvotes, downvotes, comment FROM COMMENTS WHERE contentId = $1 ORDER BY upvotes DESC", contentId);
		size_t sz = res.size();

		vector<CommentInfo> result;
		for (size_t i = min(sz, offset); i < sz && i < count; i++)
		{
			result.push_back(CommentInfo
				{
					.text = res.at(i).at("comment").as<string>(),
					.upvotes = res.at(i).at("upvotes").as<int>(),
					.downvotes = res.at(i).at("downvotes").as<int>(),
					.commentId = res.at(i).at("commentId").as<int64_t>(),
					.userId = res.at(i).at("userId").as<int64_t>()
					
				});
		}

		co_return result;
	}commit;
}

drogon::Task<CommentInfo> stend::getSingleComment(int64_t userId, int64_t commentId)
{
	transaction
	{
		CoroMapper<Comments> mapper(trans);
		CoroMapper<Content> content_mapper(trans);

		Comments comment = co_await mapper.findByPrimaryKey(commentId);

		Content content = co_await content_mapper.findByPrimaryKey(comment.getValueOfContentid());
		cb(content.getValueOfIspublic() == "1" || co_await __HasUserPermission(userId, comment.getValueOfContentid(), PERMISSION_VIEW));

		co_return CommentInfo
		{
			.text = comment.getValueOfComment(),
			.upvotes = comment.getValueOfUpvotes(),
			.downvotes = comment.getValueOfDownvotes(),
			.commentId = commentId,
			.contentId = comment.getValueOfContentid(),
		};
	}
	commit;
}

drogon::Task<> stend::upvote(int64_t userId, int64_t commentId)
{
	transaction
	{
		CoroMapper<Comments> mapper(trans);
		CoroMapper<Votes> votes_mapper(trans);
		CoroMapper<Content> content_mapper(trans);

		Comments comment = co_await mapper.findByPrimaryKey(commentId);
		Content content = co_await content_mapper.findByPrimaryKey(comment.getValueOfContentid());
		cb(content.getValueOfIspublic() == "1" || co_await __HasUserPermission(userId, comment.getValueOfContentid(), PERMISSION_VIEW));
		cb(content.getValueOfCancomment() == "1");

		int count = co_await votes_mapper.count(orm::Criteria(Votes::Cols::_userid, userId) && orm::Criteria(Votes::Cols::_commentid, comment.getValueOfCommentid()));

		if (!count)
		{
			comment.setUpvotes(comment.getValueOfUpvotes() + 1);
			co_await mapper.update(comment);

			Votes votes;
			votes.setUserid(userId);
			votes.setCommentid(commentId);
			votes.setVote("1");
			co_await votes_mapper.insert(votes);
		}
		else
		{
			Votes votes = co_await votes_mapper.findOne(orm::Criteria(Votes::Cols::_userid, userId) && orm::Criteria(Votes::Cols::_commentid, comment.getValueOfCommentid()));
			cb(votes.getValueOfVote() == "0");

			votes.setVote("1");
			co_await votes_mapper.insert(votes);

			comment.setDownvotes(comment.getValueOfDownvotes() - 1);
			comment.setUpvotes(comment.getValueOfUpvotes() + 1);
			co_await mapper.update(comment);
		}
		co_return;
	}
	commit;
}

drogon::Task<> stend::downvote(int64_t userId, int64_t commentId)
{
	transaction
	{
		CoroMapper<Comments> mapper(trans);
		CoroMapper<Votes> votes_mapper(trans);
		CoroMapper<Content> content_mapper(trans);

		Comments comment = co_await mapper.findByPrimaryKey(commentId);
		Content content = co_await content_mapper.findByPrimaryKey(comment.getValueOfContentid());
		cb(content.getValueOfIspublic() == "1" || co_await __HasUserPermission(userId, comment.getValueOfContentid(), PERMISSION_VIEW));
		cb(content.getValueOfCancomment() == "1");

		int count = co_await votes_mapper.count(orm::Criteria(Votes::Cols::_userid, userId) && orm::Criteria(Votes::Cols::_commentid, comment.getValueOfCommentid()));

		if (!count)
		{
			comment.setDownvotes(comment.getValueOfUpvotes() + 1);
			co_await mapper.update(comment);

			Votes votes;
			votes.setUserid(userId);
			votes.setCommentid(commentId);
			votes.setVote("1");
			co_await votes_mapper.insert(votes);
		}
		else
		{
			Votes votes = co_await votes_mapper.findOne(orm::Criteria(Votes::Cols::_userid, userId) && orm::Criteria(Votes::Cols::_commentid, comment.getValueOfCommentid()));
			cb(votes.getValueOfVote() == "1");

			votes.setVote("1");
			co_await votes_mapper.insert(votes);

			comment.setDownvotes(comment.getValueOfDownvotes() + 1);
			comment.setUpvotes(comment.getValueOfUpvotes() - 1);
			co_await mapper.update(comment);
		}
	}
	commit;
	co_return;

}

drogon::Task<> stend::deleteComment(int64_t userId, int64_t commentId)
{
	transaction
	{
		CoroMapper<Comments> mapper(trans);
		CoroMapper<Votes> votes_mapper(trans);

		Comments comment = co_await mapper.findByPrimaryKey(commentId);
		cb(userId == comment.getValueOfUserid());

		co_await __deleteComment(commentId, trans);
	}commit;
	co_return;
}

drogon::Task<> stend::__deleteComment(int64_t commentId, std::shared_ptr<drogon::orm::Transaction> trans)
{
	CoroMapper<Comments> mapper(trans);
	CoroMapper<Votes> votes_mapper(trans);

	co_await votes_mapper.deleteBy(orm::Criteria(Votes::Cols::_commentid, commentId));
	co_await mapper.deleteByPrimaryKey(commentId);
	co_return;
}



void stend::RegisterHttpFileUploadHandlers()
{
	drogon::app().registerHandler("/files/upload", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback) ->drogon::Task<>
		{

			cb(req->contentType() == ContentType::CT_MULTIPART_FORM_DATA);
			MultiPartParser parser;
			parser.parse(req);

			auto& map = parser.getParameters();

			Json::Value value;
			Json::Reader reader;
			reader.parse(map.at("params"), value, false);
			cb(reader.good());

			auto session = co_await __getByIdToken(value["idToken"].asString());
			int format = value["format"].asInt();
			string filename = RandomFilename(format);
			Content content;
			if (value.isMember("caption")) content.setCaption(value["caption"].asString());
			if (value.isMember("displayName")) content.setDisplayname(map.at("displayName"));
			content.setOwner(session->userId());
			content.setViews(0);
			content.setLikes(0);
			content.setDislikes(0);
			content.setFlags(0);
			content.setIspublic("0"); // temporary - will set desired value after ACL list for security reasons
			content.setCancomment("0");

			parser.getFiles()[0].saveAs(filename);

			transaction
			{
				CoroMapper<Content> content_mapper(trans);
				Content new_content = co_await content_mapper.insert(content);

				if (value.isMember("acl"))
				{
					for (Value acl : value["acl"])
					{

						co_await SetPermission(session->userId(), PermissionInfo
							{
								.contentId = new_content.getValueOfContentid(),
								.userId = co_await __userIdFromUsername(acl["user"].asString()),
								.permission = ValidPermission(acl["permission"].asInt())
							});
					}
				}

				bool need_update = false;
				if (value.isMember("isPublic") && value["isPublic"].asBool())
				{
					content.setIspublic("1");
					need_update = true;
				}
				if (value.isMember("canComment") && value["canComment"].asBool())
				{
					content.setCancomment("1");
					need_update = true;
				}
				if (need_update)co_await content_mapper.update(content);;
				co_await app().getFastDbClient()->execSqlCoro("CALL UpdateContentTsVectors()");

				Value res;
				res["contentId"] = (Int64)new_content.getValueOfContentid();
				res["success"] = true;
				callback(HttpResponse::newHttpJsonResponse(res));
				co_return;
			}
				catch (...)
			{
				remove(filename);
				trans->rollback();
				rethrow_exception(current_exception());
			}
			//
			//To do: DBUS implementation

			co_return;
		}, { Post });
	drogon::app().registerHandler("/files/download", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->drogon::Task<>
		{
			transaction
			{
				CoroMapper<Content> content_mapper(trans);
				GetJson;
				paramStr(idToken);
				paramInt64(contentId);

				auto session = co_await __getByIdToken(idToken);
				auto content = co_await content_mapper.findByPrimaryKey(contentId);

				cb(content.getValueOfOwner() == session->userId() ||
					co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_VIEW) ||
					(content.getValueOfIspublic() == "1" &&
						!co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_DENY)));

				shared_ptr<FILE> file(ca(fopen(stend::absolute(content.getValueOfFilename()).c_str(), "rb")), fclose);

				content.setViews(content.getValueOfViews() + 1);
				co_await content_mapper.update(content);

				// DBUS implementation

				callback(HttpResponse::newFileResponse(stend::absolute(content.getValueOfFilename()), "", CT_CUSTOM, GetTypeString(path(content.getValueOfFilename()).extension())));

				co_return;
			}commit;
		}, { Get });
	drogon::app().registerHandler("/files/delete", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->drogon::Task<>
		{
			transaction
			{
				CoroMapper<Content> content_mapper(trans);
				CoroMapper<Acl> acl_mapper(trans);
				CoroMapper<Comments> comment_mapper(trans);
				
				
				GetJson;
				paramStr(idToken);
				paramInt64(contentId);

				auto session = co_await __getByIdToken(idToken);
				auto content = co_await content_mapper.findByPrimaryKey(contentId);
				cb(content.getValueOfOwner() == session->userId());

				co_return;
			}
			commit;
		}, { Delete });
	drogon::app().registerHandler("/files/setFileInfo", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->drogon::Task<>
		{
			transaction
			{
				CoroMapper<Content> content_mapper(trans);
				GetJson;
				paramStr(idToken);
				paramInt64(contentId);
				bool update_vectors = false;

				auto session = co_await __getByIdToken(idToken);
				auto content = co_await content_mapper.findByPrimaryKey(contentId);
				cb(content.getValueOfOwner() == session->userId());

				if (value->isMember("displayName"))
				{
					content.setDisplayname(value->operator[]("displayName").asString());
					update_vectors = true;
				}
				if (value->isMember("caption"))
				{
					content.setCaption(value->operator[]("caption").asString());
					update_vectors = true;
				}
				if (value->isMember("isPublic"))
				{
					content.setIspublic(value->operator[]("isPublic").asBool() ? "1" : "0");
				}
				if (value->isMember("canComment"))
				{
					content.setIspublic(value->operator[]("canComment").asBool() ? "1" : "0");
				}
				if (value->isMember("acl"))
				{
					for (Value acl : value->operator[]("acl"))
					{
						co_await SetPermission(session->userId(), PermissionInfo
							{
								.contentId = content.getValueOfContentid(),
								.userId = co_await __userIdFromUsername(acl["user"].asString()),
								.permission = ValidPermission(acl["permission"].asInt())
							});
					}
				}

				co_await content_mapper.update(content);
				if (update_vectors) co_await app().getFastDbClient()->execSqlCoro("CALL UpdateContentTsVectors()");

				co_return;
			}
			commit;
		}, { Get });
	drogon::app().registerHandler("/files/like", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->drogon::Task<>
		{
			transaction
			{
				CoroMapper<Content> content_mapper(trans);
				GetJson;
				paramStr(idToken);
				paramInt64(contentId);

				auto session = co_await __getByIdToken(idToken);
				auto content = co_await content_mapper.findByPrimaryKey(contentId);
				cb(content.getValueOfOwner() == session->userId() ||
					co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_VIEW) ||
					(content.getValueOfIspublic() == "1" &&
						!co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_DENY)));

				content.setLikes(content.getValueOfLikes() + 1);
				co_await content_mapper.update(content);

				Value res;
				res["success"] = true;
				callback(HttpResponse::newHttpJsonResponse(res));
			}commit;
			co_return;
		}, { Post });
	drogon::app().registerHandler("/files/dislike", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->drogon::Task<>
		{
			transaction
			{
				CoroMapper<Content> content_mapper(co_await app().getFastDbClient()->newTransactionCoro());
				GetJson;
				paramStr(idToken);
				paramInt64(contentId);

				auto session = co_await __getByIdToken(idToken);
				auto content = co_await content_mapper.findByPrimaryKey(contentId);
				cb(content.getValueOfOwner() == session->userId() ||
					co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_VIEW) ||
					(content.getValueOfIspublic() == "1" &&
						!co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_DENY)));

				content.setDislikes(content.getValueOfDislikes() + 1);
				co_await content_mapper.update(content);

				Value res;
				res["success"] = true;
				callback(HttpResponse::newHttpJsonResponse(res));
			}
			commit;
			co_return;
		}, { Post });
	drogon::app().registerHandler("/files/flag", [](HttpRequestPtr req, std::function<void(const HttpResponsePtr&)> callback)->drogon::Task<>
		{
			transaction
			{
				CoroMapper<Content> content_mapper(co_await app().getFastDbClient()->newTransactionCoro());
				GetJson;
				paramStr(idToken);
				paramInt64(contentId);

				auto session = co_await __getByIdToken(idToken);
				auto content = co_await content_mapper.findByPrimaryKey(contentId);
				cb(content.getValueOfOwner() == session->userId() ||
					co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_VIEW) ||
					(content.getValueOfIspublic() == "1" &&
						!co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_DENY)));

				content.setFlags(content.getValueOfFlags() + 1);
				co_await content_mapper.update(content);

				Value res;
				res["success"] = true;
				callback(HttpResponse::newHttpJsonResponse(res));
			}commit;
			co_return;
		}, { Post });
}

void stend::FileUploadHandler::handleNewMessage(const WebSocketConnectionPtr& _conn, std::string&& _msg, const WebSocketMessageType& _type)
{
	async_run([conn = WebSocketConnectionPtr(_conn), msg = std::move(_msg), type = WebSocketMessageType(_type)]()->Task<>
		{
			try
			{
				switch (type)
				{
				case WebSocketMessageType::Text:
				{
					shared_ptr<Json::Value> value;
					Json::Reader reader;
					reader.parse(msg, *value);
					if (!reader.good()) throw runtime_error(reader.getFormattedErrorMessages());

					paramStr(operation);

					if (operation == "write")
					{
						WriteSocketContextPtr ctx;
						conn->setContext(ctx);

						paramStr(idToken);
						paramInt(format);
						paramStr(displayName);
						paramStr(caption);
						paramBool(isPublic);

						ctx->filename = RandomFilename(format);

						auto session = co_await __getByIdToken(idToken);
						ctx->content.setOwner(session->userId());
						ctx->content.setDisplayname(displayName);
						ctx->content.setCaption(caption);
						ctx->content.setViews(0);
						ctx->content.setLikes(0);
						ctx->content.setDislikes(0);
						ctx->content.setFlags(0);
						ctx->content.setFilename(ctx->filename);

						if (value->isMember("acl"))
						{
							Value acl = value->operator[]("acl");
							ctx->acl_list.resize(acl.size());
							int i = 0;
							for (Value val : acl) ctx->acl_list[i++] =
							{
								.userId = co_await __userIdFromUsername(val["username"].asString()),
								.permission = ValidPermission(val["permission"].asInt())
							};
						}

						ctx->file = shared_ptr<FILE>(ca(fopen(stend::absolute(ctx->filename).c_str(), "rwb")), fclose);

						conn->send(R"({"success":true,"expect-operation":"finalize"})");
					}
					else if (operation == "read")
					{
						transaction
						{
							CoroMapper<Content> content_mapper(trans);

							paramInt64(contentId);
							paramStr(idToken);

							auto session = co_await __getByIdToken(idToken);
							auto content = co_await content_mapper.findByPrimaryKey(contentId);

							cb(content.getValueOfOwner() == session->userId() ||
								co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_VIEW) ||
								(content.getValueOfIspublic() == "1" &&
									!co_await __HasUserPermission(session->userId(), content.getValueOfContentid(), PERMISSION_DENY)));

							shared_ptr<FILE> file(ca(fopen(stend::absolute(content.getValueOfFilename()).c_str(), "rb")), fclose);

							content.setViews(content.getValueOfViews() + 1);
							co_await content_mapper.update(content);

							// DBUS implementation

							trantor::Func lambda = [file, lambda, conn]
							{
								binary _cache(conf->READ_CACHE);
								size_t sz = co(fread(_cache.data(), _cache.size(), 1, file.get()));
								conn->send(_cache.data(), _cache.size(), WebSocketMessageType::Binary);
								if (!feof(file.get())) drogon::app().getLoop()->queueInLoop(lambda);
							};
							drogon::app().getLoop()->queueInLoop(lambda);
						}commit;
					}
					else if (operation == "finalize")
					{
						WriteSocketContextPtr ctx = conn->getContext<WriteSocketContext>();
						if (ctx)
						{
							transaction
							{
								CoroMapper<Content> content_mapper(trans);

								switch (ctx->format)
								{
								case FILE_TYPE_VIDEO:
									break;
								case FILE_TYPE_AUDIO:
									break;
								case FILE_TYPE_PICTURE:
									break;
								default:
									throw runtime_error("invalid format");
								}
								Content new_content = co_await content_mapper.insert(ctx->content);

								//
								//To do: DBUS implementation

								ctx->unlink_on_close = false;

								for (PermissionInfo info : ctx->acl_list)
								{
									info.contentId = ctx->content.getValueOfContentid();
									co_await SetPermission(ctx->content.getValueOfOwner(),info);
								}

								Value res;
								res["contentId"] = (Int64)new_content.getValueOfContentid();
								res["success"] = true;
								conn->send(writeString(StreamWriterBuilder(), res));
							}
							catch (...)
							{
								conn->forceClose();
								trans->rollback();
								rethrow_exception(current_exception());
							}

							break;
						}
						else
						{
							conn->forceClose();
							break;
						}
					}
					else if (operation == "abort")
					{
						conn->shutdown();
					}
					else conn->forceClose();
				}
				break;
				case WebSocketMessageType::Binary:
				{
					auto ctx = conn->getContext<WriteSocketContext>();
					co(fwrite(msg.c_str(), msg.length(), 1, ctx->file.get()));
				}
				break;
				case WebSocketMessageType::Ping:
					conn->send(R"({"success": true })", WebSocketMessageType::Pong);
					break;
				default:
					conn->forceClose();
					break;
				}
			}
			catch (exception& ex)
			{
				LOG_WARN << ex.what();
				conn->forceClose();
			}
			co_return;
		});
}

void stend::FileUploadHandler::handleNewConnection(const HttpRequestPtr& req, const WebSocketConnectionPtr& conn)
{
}

void stend::FileUploadHandler::handleConnectionClosed(const WebSocketConnectionPtr& _conn)
{
}




drogon::Task<std::vector<PermissionInfo>> stend::GetAllPermissionsForUser(binary idTokenOwner, int64_t userId)
{
	
}

drogon::Task<std::vector<PermissionInfo>> stend::GetAllPermissionsForFile(binary idTokenOwner, int64_t fileId)
{
	
}

