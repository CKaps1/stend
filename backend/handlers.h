#pragma once
#include "binary.h"
#include "SessionCache.h"
#include "Users.h"
#include <sys/types.h>
#include <drogon/drogon.h>
#include <drogon/orm/CoroMapper.h>
#include <drogon/WebSocketController.h>

#define GetJson std::shared_ptr<Json::Value> value = _getJson(req)
#define checkJson(str) __checkJson(value,str)
#define paramStr(name) checkJson(#name);auto name = value->operator[](#name).asString()
#define paramInt(name)  checkJson(#name);auto name = value->operator[](#name).asInt()
#define paramInt64(name) checkJson(#name);auto name = value->operator[](#name).asInt64()
#define paramDouble(name) checkJson(#name);auto name = value->operator[](#name).asDouble()
#define paramBool(name) checkJson(#name);auto name = value->operator[](#name).asBool()
#define paramFloat(name) checkJson(#name);auto name = value->operator[](#name).asFloat()

#define PERMISSION_NONE 0
#define PERMISSION_DENY 1
#define PERMISSION_VIEW 2

typedef std::shared_ptr<drogon::orm::Transaction> transptr;

namespace stend
{
    class FileUploadHandler : public drogon::WebSocketController<FileUploadHandler>
    {
    public:
        WS_PATH_LIST_BEGIN
            WS_PATH_ADD("/files/upload");
        WS_PATH_ADD("/files/download");
        WS_PATH_LIST_END
            void handleNewMessage(const drogon::WebSocketConnectionPtr&, std::string&&, const drogon::WebSocketMessageType&) override;
        void handleNewConnection(const drogon::HttpRequestPtr&, const drogon::WebSocketConnectionPtr&) override;
        void handleConnectionClosed(const drogon::WebSocketConnectionPtr&) override;
    };
    void RegisterHttpFileUploadHandlers();

    struct CommentInfo
    {
        std::string text;
        int upvotes, downvotes;
        int64_t commentId, userId, contentId;
    };

    struct PermissionInfo
    {
        int64_t contentId, userId;
        short permission;
    };

    struct LoginInfo
    {
        binary refreshToken, idToken;
        int64_t SessionID;
        trantor::Date expiry;
    };

	std::shared_ptr<Json::Value> _getJson(const drogon::HttpRequestPtr& request);
	void __checkJson(const std::shared_ptr<Json::Value> val, std::string name);
    std::string RandomFilename(int format);
    static std::string absolute(std::string local);

	void RegisterAuthenticationHandlers();
	void RegisterCommentTagHandlers();

    drogon::Task<> CreateUser(std::string username, std::string email, std::string password);
    drogon::Task<LoginInfo> LoginByUsername(std::string username, std::string password);
    drogon::Task<LoginInfo> LoginByEmail(std::string email, std::string password);
    drogon::Task<> Logout(binary refreshToken, int64_t SessionId);
    drogon::Task<> LogoutAll(binary refreshToken, int64_t SessionId);
    drogon::Task<LoginInfo> Refresh(binary refreshToken, int64_t SessionId);
    drogon::Task<> __DeleteAccount(int64_t userId);

    drogon::Task<> SetPermission(int64_t idOwner, PermissionInfo perm);
    drogon::Task<PermissionInfo> GetPermission(binary idTokenOwner, int64_t fileId, int64_t userId);
    drogon::Task<std::vector<PermissionInfo>> GetAllPermissionsForUser(binary idTokenOwner, int64_t userId);
    drogon::Task<std::vector<PermissionInfo>> GetAllPermissionsForFile(binary idTokenOwner, int64_t fileId);
    drogon::Task<bool> __HasUserPermission(int64_t userId, int64_t fileId, short permission);
    drogon::Task<> __deletePermissions(int64_t contentId, std::shared_ptr<drogon::orm::Transaction> trans);

    drogon::Task<StendSessionPtr> __getByIdToken(binary idToken);
    drogon::Task<int64_t> __userIdFromUsername(std::string username);
    drogon::Task<drogon_model::stend::Users> userInfo(int64_t userId);
    drogon::Task<> __deleteFile(int64_t fileId, transptr trans);

    drogon::Task<int64_t> addComment(int64_t userId, int64_t contentId, std::string text);
    drogon::Task<std::vector<CommentInfo>> getComments(int64_t userId, int64_t contentId, size_t offset, size_t count);
    drogon::Task<CommentInfo> getSingleComment(int64_t userId, int64_t commentId);
    drogon::Task<> upvote(int64_t userId, int64_t commentId);
    drogon::Task<> downvote(int64_t userId, int64_t commentId);
    drogon::Task<> deleteComment(int64_t userId, int64_t commentId);
    drogon::Task<> __deleteComment(int64_t commentId, std::shared_ptr<drogon::orm::Transaction>);

    drogon::Task<> setTags(int64_t userId, int64_t contentId, std::vector<std::string> tags);
    drogon::Task<std::vector<std::string>> getTags(int64_t userId, int64_t contentId);
    drogon::Task<> removeTags(int64_t userId, int64_t contentId, std::vector<std::string> tags);
    drogon::Task<> removeAllTags(int64_t userId, int64_t contentId);
    drogon::Task<> __removeAllTags(int64_t contentId, transptr trans);
}