/**
 *
 *  Sessions.cc
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#include "Sessions.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
using namespace drogon::orm;
using namespace drogon_model::stend;

const std::string Sessions::Cols::_sessionid = "sessionid";
const std::string Sessions::Cols::_userid = "userid";
const std::string Sessions::Cols::_refreshkeyhash = "refreshkeyhash";
const std::string Sessions::Cols::_refreshkeysalt = "refreshkeysalt";
const std::string Sessions::Cols::_expirydate = "expirydate";
const std::string Sessions::primaryKeyName = "sessionid";
const bool Sessions::hasPrimaryKey = true;
const std::string Sessions::tableName = "sessions";

const std::vector<typename Sessions::MetaData> Sessions::metaData_={
{"sessionid","int64_t","bigint",8,1,1,1},
{"userid","int64_t","bigint",8,0,0,1},
{"refreshkeyhash","std::vector<char>","bytea",0,0,0,1},
{"refreshkeysalt","std::vector<char>","bytea",0,0,0,1},
{"expirydate","::trantor::Date","date",0,0,0,1}
};
const std::string &Sessions::getColumnName(size_t index) noexcept(false)
{
    assert(index < metaData_.size());
    return metaData_[index].colName_;
}
Sessions::Sessions(const Row &r, const ssize_t indexOffset) noexcept
{
    if(indexOffset < 0)
    {
        if(!r["sessionid"].isNull())
        {
            sessionid_=std::make_shared<int64_t>(r["sessionid"].as<int64_t>());
        }
        if(!r["userid"].isNull())
        {
            userid_=std::make_shared<int64_t>(r["userid"].as<int64_t>());
        }
        if(!r["refreshkeyhash"].isNull())
        {
            auto str = r["refreshkeyhash"].as<string_view>();
            if(str.length()>=2&&
                str[0]=='\\'&&str[1]=='x')
            {
                refreshkeyhash_=std::make_shared<std::vector<char>>(drogon::utils::hexToBinaryVector(str.data()+2,str.length()-2));
            }
        }
        if(!r["refreshkeysalt"].isNull())
        {
            auto str = r["refreshkeysalt"].as<string_view>();
            if(str.length()>=2&&
                str[0]=='\\'&&str[1]=='x')
            {
                refreshkeysalt_=std::make_shared<std::vector<char>>(drogon::utils::hexToBinaryVector(str.data()+2,str.length()-2));
            }
        }
        if(!r["expirydate"].isNull())
        {
            auto daysStr = r["expirydate"].as<std::string>();
            struct tm stm;
            memset(&stm,0,sizeof(stm));
            strptime(daysStr.c_str(),"%Y-%m-%d",&stm);
            time_t t = mktime(&stm);
            expirydate_=std::make_shared<::trantor::Date>(t*1000000);
        }
    }
    else
    {
        size_t offset = (size_t)indexOffset;
        if(offset + 5 > r.size())
        {
            LOG_FATAL << "Invalid SQL result for this model";
            return;
        }
        size_t index;
        index = offset + 0;
        if(!r[index].isNull())
        {
            sessionid_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
        index = offset + 1;
        if(!r[index].isNull())
        {
            userid_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
        index = offset + 2;
        if(!r[index].isNull())
        {
            auto str = r[index].as<string_view>();
            if(str.length()>=2&&
                str[0]=='\\'&&str[1]=='x')
            {
                refreshkeyhash_=std::make_shared<std::vector<char>>(drogon::utils::hexToBinaryVector(str.data()+2,str.length()-2));
            }
        }
        index = offset + 3;
        if(!r[index].isNull())
        {
            auto str = r[index].as<string_view>();
            if(str.length()>=2&&
                str[0]=='\\'&&str[1]=='x')
            {
                refreshkeysalt_=std::make_shared<std::vector<char>>(drogon::utils::hexToBinaryVector(str.data()+2,str.length()-2));
            }
        }
        index = offset + 4;
        if(!r[index].isNull())
        {
            auto daysStr = r[index].as<std::string>();
            struct tm stm;
            memset(&stm,0,sizeof(stm));
            strptime(daysStr.c_str(),"%Y-%m-%d",&stm);
            time_t t = mktime(&stm);
            expirydate_=std::make_shared<::trantor::Date>(t*1000000);
        }
    }

}

Sessions::Sessions(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 5)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        dirtyFlag_[0] = true;
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            sessionid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[0]].asInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            userid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[1]].asInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            auto str = pJson[pMasqueradingVector[2]].asString();
            refreshkeyhash_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            auto str = pJson[pMasqueradingVector[3]].asString();
            refreshkeysalt_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(!pMasqueradingVector[4].empty() && pJson.isMember(pMasqueradingVector[4]))
    {
        dirtyFlag_[4] = true;
        if(!pJson[pMasqueradingVector[4]].isNull())
        {
            auto daysStr = pJson[pMasqueradingVector[4]].asString();
            struct tm stm;
            memset(&stm,0,sizeof(stm));
            strptime(daysStr.c_str(),"%Y-%m-%d",&stm);
            time_t t = mktime(&stm);
            expirydate_=std::make_shared<::trantor::Date>(t*1000000);
        }
    }
}

Sessions::Sessions(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("sessionid"))
    {
        dirtyFlag_[0]=true;
        if(!pJson["sessionid"].isNull())
        {
            sessionid_=std::make_shared<int64_t>((int64_t)pJson["sessionid"].asInt64());
        }
    }
    if(pJson.isMember("userid"))
    {
        dirtyFlag_[1]=true;
        if(!pJson["userid"].isNull())
        {
            userid_=std::make_shared<int64_t>((int64_t)pJson["userid"].asInt64());
        }
    }
    if(pJson.isMember("refreshkeyhash"))
    {
        dirtyFlag_[2]=true;
        if(!pJson["refreshkeyhash"].isNull())
        {
            auto str = pJson["refreshkeyhash"].asString();
            refreshkeyhash_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(pJson.isMember("refreshkeysalt"))
    {
        dirtyFlag_[3]=true;
        if(!pJson["refreshkeysalt"].isNull())
        {
            auto str = pJson["refreshkeysalt"].asString();
            refreshkeysalt_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(pJson.isMember("expirydate"))
    {
        dirtyFlag_[4]=true;
        if(!pJson["expirydate"].isNull())
        {
            auto daysStr = pJson["expirydate"].asString();
            struct tm stm;
            memset(&stm,0,sizeof(stm));
            strptime(daysStr.c_str(),"%Y-%m-%d",&stm);
            time_t t = mktime(&stm);
            expirydate_=std::make_shared<::trantor::Date>(t*1000000);
        }
    }
}

void Sessions::updateByMasqueradedJson(const Json::Value &pJson,
                                            const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 5)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            sessionid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[0]].asInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            userid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[1]].asInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            auto str = pJson[pMasqueradingVector[2]].asString();
            refreshkeyhash_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            auto str = pJson[pMasqueradingVector[3]].asString();
            refreshkeysalt_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(!pMasqueradingVector[4].empty() && pJson.isMember(pMasqueradingVector[4]))
    {
        dirtyFlag_[4] = true;
        if(!pJson[pMasqueradingVector[4]].isNull())
        {
            auto daysStr = pJson[pMasqueradingVector[4]].asString();
            struct tm stm;
            memset(&stm,0,sizeof(stm));
            strptime(daysStr.c_str(),"%Y-%m-%d",&stm);
            time_t t = mktime(&stm);
            expirydate_=std::make_shared<::trantor::Date>(t*1000000);
        }
    }
}

void Sessions::updateByJson(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("sessionid"))
    {
        if(!pJson["sessionid"].isNull())
        {
            sessionid_=std::make_shared<int64_t>((int64_t)pJson["sessionid"].asInt64());
        }
    }
    if(pJson.isMember("userid"))
    {
        dirtyFlag_[1] = true;
        if(!pJson["userid"].isNull())
        {
            userid_=std::make_shared<int64_t>((int64_t)pJson["userid"].asInt64());
        }
    }
    if(pJson.isMember("refreshkeyhash"))
    {
        dirtyFlag_[2] = true;
        if(!pJson["refreshkeyhash"].isNull())
        {
            auto str = pJson["refreshkeyhash"].asString();
            refreshkeyhash_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(pJson.isMember("refreshkeysalt"))
    {
        dirtyFlag_[3] = true;
        if(!pJson["refreshkeysalt"].isNull())
        {
            auto str = pJson["refreshkeysalt"].asString();
            refreshkeysalt_=std::make_shared<std::vector<char>>(drogon::utils::base64DecodeToVector(str));
        }
    }
    if(pJson.isMember("expirydate"))
    {
        dirtyFlag_[4] = true;
        if(!pJson["expirydate"].isNull())
        {
            auto daysStr = pJson["expirydate"].asString();
            struct tm stm;
            memset(&stm,0,sizeof(stm));
            strptime(daysStr.c_str(),"%Y-%m-%d",&stm);
            time_t t = mktime(&stm);
            expirydate_=std::make_shared<::trantor::Date>(t*1000000);
        }
    }
}

const int64_t &Sessions::getValueOfSessionid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(sessionid_)
        return *sessionid_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Sessions::getSessionid() const noexcept
{
    return sessionid_;
}
void Sessions::setSessionid(const int64_t &pSessionid) noexcept
{
    sessionid_ = std::make_shared<int64_t>(pSessionid);
    dirtyFlag_[0] = true;
}
const typename Sessions::PrimaryKeyType & Sessions::getPrimaryKey() const
{
    assert(sessionid_);
    return *sessionid_;
}

const int64_t &Sessions::getValueOfUserid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(userid_)
        return *userid_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Sessions::getUserid() const noexcept
{
    return userid_;
}
void Sessions::setUserid(const int64_t &pUserid) noexcept
{
    userid_ = std::make_shared<int64_t>(pUserid);
    dirtyFlag_[1] = true;
}

const std::vector<char> &Sessions::getValueOfRefreshkeyhash() const noexcept
{
    const static std::vector<char> defaultValue = std::vector<char>();
    if(refreshkeyhash_)
        return *refreshkeyhash_;
    return defaultValue;
}
std::string Sessions::getValueOfRefreshkeyhashAsString() const noexcept
{
    const static std::string defaultValue = std::string();
    if(refreshkeyhash_)
        return std::string(refreshkeyhash_->data(),refreshkeyhash_->size());
    return defaultValue;
}
const std::shared_ptr<std::vector<char>> &Sessions::getRefreshkeyhash() const noexcept
{
    return refreshkeyhash_;
}
void Sessions::setRefreshkeyhash(const std::vector<char> &pRefreshkeyhash) noexcept
{
    refreshkeyhash_ = std::make_shared<std::vector<char>>(pRefreshkeyhash);
    dirtyFlag_[2] = true;
}
void Sessions::setRefreshkeyhash(const std::string &pRefreshkeyhash) noexcept
{
    refreshkeyhash_ = std::make_shared<std::vector<char>>(pRefreshkeyhash.c_str(),pRefreshkeyhash.c_str()+pRefreshkeyhash.length());
    dirtyFlag_[2] = true;
}

const std::vector<char> &Sessions::getValueOfRefreshkeysalt() const noexcept
{
    const static std::vector<char> defaultValue = std::vector<char>();
    if(refreshkeysalt_)
        return *refreshkeysalt_;
    return defaultValue;
}
std::string Sessions::getValueOfRefreshkeysaltAsString() const noexcept
{
    const static std::string defaultValue = std::string();
    if(refreshkeysalt_)
        return std::string(refreshkeysalt_->data(),refreshkeysalt_->size());
    return defaultValue;
}
const std::shared_ptr<std::vector<char>> &Sessions::getRefreshkeysalt() const noexcept
{
    return refreshkeysalt_;
}
void Sessions::setRefreshkeysalt(const std::vector<char> &pRefreshkeysalt) noexcept
{
    refreshkeysalt_ = std::make_shared<std::vector<char>>(pRefreshkeysalt);
    dirtyFlag_[3] = true;
}
void Sessions::setRefreshkeysalt(const std::string &pRefreshkeysalt) noexcept
{
    refreshkeysalt_ = std::make_shared<std::vector<char>>(pRefreshkeysalt.c_str(),pRefreshkeysalt.c_str()+pRefreshkeysalt.length());
    dirtyFlag_[3] = true;
}

const ::trantor::Date &Sessions::getValueOfExpirydate() const noexcept
{
    const static ::trantor::Date defaultValue = ::trantor::Date();
    if(expirydate_)
        return *expirydate_;
    return defaultValue;
}
const std::shared_ptr<::trantor::Date> &Sessions::getExpirydate() const noexcept
{
    return expirydate_;
}
void Sessions::setExpirydate(const ::trantor::Date &pExpirydate) noexcept
{
    expirydate_ = std::make_shared<::trantor::Date>(pExpirydate.roundDay());
    dirtyFlag_[4] = true;
}

void Sessions::updateId(const uint64_t id)
{
}

const std::vector<std::string> &Sessions::insertColumns() noexcept
{
    static const std::vector<std::string> inCols={
        "userid",
        "refreshkeyhash",
        "refreshkeysalt",
        "expirydate"
    };
    return inCols;
}

void Sessions::outputArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getUserid())
        {
            binder << getValueOfUserid();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getRefreshkeyhash())
        {
            binder << getValueOfRefreshkeyhash();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getRefreshkeysalt())
        {
            binder << getValueOfRefreshkeysalt();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[4])
    {
        if(getExpirydate())
        {
            binder << getValueOfExpirydate();
        }
        else
        {
            binder << nullptr;
        }
    }
}

const std::vector<std::string> Sessions::updateColumns() const
{
    std::vector<std::string> ret;
    if(dirtyFlag_[1])
    {
        ret.push_back(getColumnName(1));
    }
    if(dirtyFlag_[2])
    {
        ret.push_back(getColumnName(2));
    }
    if(dirtyFlag_[3])
    {
        ret.push_back(getColumnName(3));
    }
    if(dirtyFlag_[4])
    {
        ret.push_back(getColumnName(4));
    }
    return ret;
}

void Sessions::updateArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getUserid())
        {
            binder << getValueOfUserid();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getRefreshkeyhash())
        {
            binder << getValueOfRefreshkeyhash();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getRefreshkeysalt())
        {
            binder << getValueOfRefreshkeysalt();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[4])
    {
        if(getExpirydate())
        {
            binder << getValueOfExpirydate();
        }
        else
        {
            binder << nullptr;
        }
    }
}
Json::Value Sessions::toJson() const
{
    Json::Value ret;
    if(getSessionid())
    {
        ret["sessionid"]=(Json::Int64)getValueOfSessionid();
    }
    else
    {
        ret["sessionid"]=Json::Value();
    }
    if(getUserid())
    {
        ret["userid"]=(Json::Int64)getValueOfUserid();
    }
    else
    {
        ret["userid"]=Json::Value();
    }
    if(getRefreshkeyhash())
    {
        ret["refreshkeyhash"]=drogon::utils::base64Encode((const unsigned char *)getRefreshkeyhash()->data(),getRefreshkeyhash()->size());
    }
    else
    {
        ret["refreshkeyhash"]=Json::Value();
    }
    if(getRefreshkeysalt())
    {
        ret["refreshkeysalt"]=drogon::utils::base64Encode((const unsigned char *)getRefreshkeysalt()->data(),getRefreshkeysalt()->size());
    }
    else
    {
        ret["refreshkeysalt"]=Json::Value();
    }
    if(getExpirydate())
    {
        ret["expirydate"]=getExpirydate()->toDbStringLocal();
    }
    else
    {
        ret["expirydate"]=Json::Value();
    }
    return ret;
}

Json::Value Sessions::toMasqueradedJson(
    const std::vector<std::string> &pMasqueradingVector) const
{
    Json::Value ret;
    if(pMasqueradingVector.size() == 5)
    {
        if(!pMasqueradingVector[0].empty())
        {
            if(getSessionid())
            {
                ret[pMasqueradingVector[0]]=(Json::Int64)getValueOfSessionid();
            }
            else
            {
                ret[pMasqueradingVector[0]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[1].empty())
        {
            if(getUserid())
            {
                ret[pMasqueradingVector[1]]=(Json::Int64)getValueOfUserid();
            }
            else
            {
                ret[pMasqueradingVector[1]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[2].empty())
        {
            if(getRefreshkeyhash())
            {
                ret[pMasqueradingVector[2]]=drogon::utils::base64Encode((const unsigned char *)getRefreshkeyhash()->data(),getRefreshkeyhash()->size());
            }
            else
            {
                ret[pMasqueradingVector[2]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[3].empty())
        {
            if(getRefreshkeysalt())
            {
                ret[pMasqueradingVector[3]]=drogon::utils::base64Encode((const unsigned char *)getRefreshkeysalt()->data(),getRefreshkeysalt()->size());
            }
            else
            {
                ret[pMasqueradingVector[3]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[4].empty())
        {
            if(getExpirydate())
            {
                ret[pMasqueradingVector[4]]=getExpirydate()->toDbStringLocal();
            }
            else
            {
                ret[pMasqueradingVector[4]]=Json::Value();
            }
        }
        return ret;
    }
    LOG_ERROR << "Masquerade failed";
    if(getSessionid())
    {
        ret["sessionid"]=(Json::Int64)getValueOfSessionid();
    }
    else
    {
        ret["sessionid"]=Json::Value();
    }
    if(getUserid())
    {
        ret["userid"]=(Json::Int64)getValueOfUserid();
    }
    else
    {
        ret["userid"]=Json::Value();
    }
    if(getRefreshkeyhash())
    {
        ret["refreshkeyhash"]=drogon::utils::base64Encode((const unsigned char *)getRefreshkeyhash()->data(),getRefreshkeyhash()->size());
    }
    else
    {
        ret["refreshkeyhash"]=Json::Value();
    }
    if(getRefreshkeysalt())
    {
        ret["refreshkeysalt"]=drogon::utils::base64Encode((const unsigned char *)getRefreshkeysalt()->data(),getRefreshkeysalt()->size());
    }
    else
    {
        ret["refreshkeysalt"]=Json::Value();
    }
    if(getExpirydate())
    {
        ret["expirydate"]=getExpirydate()->toDbStringLocal();
    }
    else
    {
        ret["expirydate"]=Json::Value();
    }
    return ret;
}

bool Sessions::validateJsonForCreation(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("sessionid"))
    {
        if(!validJsonOfField(0, "sessionid", pJson["sessionid"], err, true))
            return false;
    }
    if(pJson.isMember("userid"))
    {
        if(!validJsonOfField(1, "userid", pJson["userid"], err, true))
            return false;
    }
    else
    {
        err="The userid column cannot be null";
        return false;
    }
    if(pJson.isMember("refreshkeyhash"))
    {
        if(!validJsonOfField(2, "refreshkeyhash", pJson["refreshkeyhash"], err, true))
            return false;
    }
    else
    {
        err="The refreshkeyhash column cannot be null";
        return false;
    }
    if(pJson.isMember("refreshkeysalt"))
    {
        if(!validJsonOfField(3, "refreshkeysalt", pJson["refreshkeysalt"], err, true))
            return false;
    }
    else
    {
        err="The refreshkeysalt column cannot be null";
        return false;
    }
    if(pJson.isMember("expirydate"))
    {
        if(!validJsonOfField(4, "expirydate", pJson["expirydate"], err, true))
            return false;
    }
    else
    {
        err="The expirydate column cannot be null";
        return false;
    }
    return true;
}
bool Sessions::validateMasqueradedJsonForCreation(const Json::Value &pJson,
                                                  const std::vector<std::string> &pMasqueradingVector,
                                                  std::string &err)
{
    if(pMasqueradingVector.size() != 5)
    {
        err = "Bad masquerading vector";
        return false;
    }
    try {
      if(!pMasqueradingVector[0].empty())
      {
          if(pJson.isMember(pMasqueradingVector[0]))
          {
              if(!validJsonOfField(0, pMasqueradingVector[0], pJson[pMasqueradingVector[0]], err, true))
                  return false;
          }
      }
      if(!pMasqueradingVector[1].empty())
      {
          if(pJson.isMember(pMasqueradingVector[1]))
          {
              if(!validJsonOfField(1, pMasqueradingVector[1], pJson[pMasqueradingVector[1]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[1] + " column cannot be null";
            return false;
        }
      }
      if(!pMasqueradingVector[2].empty())
      {
          if(pJson.isMember(pMasqueradingVector[2]))
          {
              if(!validJsonOfField(2, pMasqueradingVector[2], pJson[pMasqueradingVector[2]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[2] + " column cannot be null";
            return false;
        }
      }
      if(!pMasqueradingVector[3].empty())
      {
          if(pJson.isMember(pMasqueradingVector[3]))
          {
              if(!validJsonOfField(3, pMasqueradingVector[3], pJson[pMasqueradingVector[3]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[3] + " column cannot be null";
            return false;
        }
      }
      if(!pMasqueradingVector[4].empty())
      {
          if(pJson.isMember(pMasqueradingVector[4]))
          {
              if(!validJsonOfField(4, pMasqueradingVector[4], pJson[pMasqueradingVector[4]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[4] + " column cannot be null";
            return false;
        }
      }
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Sessions::validateJsonForUpdate(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("sessionid"))
    {
        if(!validJsonOfField(0, "sessionid", pJson["sessionid"], err, false))
            return false;
    }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
    if(pJson.isMember("userid"))
    {
        if(!validJsonOfField(1, "userid", pJson["userid"], err, false))
            return false;
    }
    if(pJson.isMember("refreshkeyhash"))
    {
        if(!validJsonOfField(2, "refreshkeyhash", pJson["refreshkeyhash"], err, false))
            return false;
    }
    if(pJson.isMember("refreshkeysalt"))
    {
        if(!validJsonOfField(3, "refreshkeysalt", pJson["refreshkeysalt"], err, false))
            return false;
    }
    if(pJson.isMember("expirydate"))
    {
        if(!validJsonOfField(4, "expirydate", pJson["expirydate"], err, false))
            return false;
    }
    return true;
}
bool Sessions::validateMasqueradedJsonForUpdate(const Json::Value &pJson,
                                                const std::vector<std::string> &pMasqueradingVector,
                                                std::string &err)
{
    if(pMasqueradingVector.size() != 5)
    {
        err = "Bad masquerading vector";
        return false;
    }
    try {
      if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
      {
          if(!validJsonOfField(0, pMasqueradingVector[0], pJson[pMasqueradingVector[0]], err, false))
              return false;
      }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
      if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
      {
          if(!validJsonOfField(1, pMasqueradingVector[1], pJson[pMasqueradingVector[1]], err, false))
              return false;
      }
      if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
      {
          if(!validJsonOfField(2, pMasqueradingVector[2], pJson[pMasqueradingVector[2]], err, false))
              return false;
      }
      if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
      {
          if(!validJsonOfField(3, pMasqueradingVector[3], pJson[pMasqueradingVector[3]], err, false))
              return false;
      }
      if(!pMasqueradingVector[4].empty() && pJson.isMember(pMasqueradingVector[4]))
      {
          if(!validJsonOfField(4, pMasqueradingVector[4], pJson[pMasqueradingVector[4]], err, false))
              return false;
      }
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Sessions::validJsonOfField(size_t index,
                                const std::string &fieldName,
                                const Json::Value &pJson,
                                std::string &err,
                                bool isForCreation)
{
    switch(index)
    {
        case 0:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(isForCreation)
            {
                err="The automatic primary key cannot be set";
                return false;
            }
            if(!pJson.isInt64())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 1:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isInt64())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 2:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isString())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 3:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isString())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 4:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isString())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        default:
            err="Internal error in the server";
            return false;
            break;
    }
    return true;
}
