/**
 *
 *  Tagassociations.cc
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#include "Tagassociations.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
using namespace drogon::orm;
using namespace drogon_model::stend;

const std::string Tagassociations::Cols::_associd = "associd";
const std::string Tagassociations::Cols::_tagid = "tagid";
const std::string Tagassociations::Cols::_contentid = "contentid";
const std::string Tagassociations::primaryKeyName = "associd";
const bool Tagassociations::hasPrimaryKey = true;
const std::string Tagassociations::tableName = "tagassociations";

const std::vector<typename Tagassociations::MetaData> Tagassociations::metaData_={
{"associd","int64_t","bigint",8,1,1,1},
{"tagid","int64_t","bigint",8,0,0,1},
{"contentid","int64_t","bigint",8,0,0,1}
};
const std::string &Tagassociations::getColumnName(size_t index) noexcept(false)
{
    assert(index < metaData_.size());
    return metaData_[index].colName_;
}
Tagassociations::Tagassociations(const Row &r, const ssize_t indexOffset) noexcept
{
    if(indexOffset < 0)
    {
        if(!r["associd"].isNull())
        {
            associd_=std::make_shared<int64_t>(r["associd"].as<int64_t>());
        }
        if(!r["tagid"].isNull())
        {
            tagid_=std::make_shared<int64_t>(r["tagid"].as<int64_t>());
        }
        if(!r["contentid"].isNull())
        {
            contentid_=std::make_shared<int64_t>(r["contentid"].as<int64_t>());
        }
    }
    else
    {
        size_t offset = (size_t)indexOffset;
        if(offset + 3 > r.size())
        {
            LOG_FATAL << "Invalid SQL result for this model";
            return;
        }
        size_t index;
        index = offset + 0;
        if(!r[index].isNull())
        {
            associd_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
        index = offset + 1;
        if(!r[index].isNull())
        {
            tagid_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
        index = offset + 2;
        if(!r[index].isNull())
        {
            contentid_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
    }

}

Tagassociations::Tagassociations(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 3)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        dirtyFlag_[0] = true;
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            associd_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[0]].asInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            tagid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[1]].asInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            contentid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[2]].asInt64());
        }
    }
}

Tagassociations::Tagassociations(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("associd"))
    {
        dirtyFlag_[0]=true;
        if(!pJson["associd"].isNull())
        {
            associd_=std::make_shared<int64_t>((int64_t)pJson["associd"].asInt64());
        }
    }
    if(pJson.isMember("tagid"))
    {
        dirtyFlag_[1]=true;
        if(!pJson["tagid"].isNull())
        {
            tagid_=std::make_shared<int64_t>((int64_t)pJson["tagid"].asInt64());
        }
    }
    if(pJson.isMember("contentid"))
    {
        dirtyFlag_[2]=true;
        if(!pJson["contentid"].isNull())
        {
            contentid_=std::make_shared<int64_t>((int64_t)pJson["contentid"].asInt64());
        }
    }
}

void Tagassociations::updateByMasqueradedJson(const Json::Value &pJson,
                                            const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 3)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            associd_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[0]].asInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            tagid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[1]].asInt64());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            contentid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[2]].asInt64());
        }
    }
}

void Tagassociations::updateByJson(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("associd"))
    {
        if(!pJson["associd"].isNull())
        {
            associd_=std::make_shared<int64_t>((int64_t)pJson["associd"].asInt64());
        }
    }
    if(pJson.isMember("tagid"))
    {
        dirtyFlag_[1] = true;
        if(!pJson["tagid"].isNull())
        {
            tagid_=std::make_shared<int64_t>((int64_t)pJson["tagid"].asInt64());
        }
    }
    if(pJson.isMember("contentid"))
    {
        dirtyFlag_[2] = true;
        if(!pJson["contentid"].isNull())
        {
            contentid_=std::make_shared<int64_t>((int64_t)pJson["contentid"].asInt64());
        }
    }
}

const int64_t &Tagassociations::getValueOfAssocid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(associd_)
        return *associd_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Tagassociations::getAssocid() const noexcept
{
    return associd_;
}
void Tagassociations::setAssocid(const int64_t &pAssocid) noexcept
{
    associd_ = std::make_shared<int64_t>(pAssocid);
    dirtyFlag_[0] = true;
}
const typename Tagassociations::PrimaryKeyType & Tagassociations::getPrimaryKey() const
{
    assert(associd_);
    return *associd_;
}

const int64_t &Tagassociations::getValueOfTagid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(tagid_)
        return *tagid_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Tagassociations::getTagid() const noexcept
{
    return tagid_;
}
void Tagassociations::setTagid(const int64_t &pTagid) noexcept
{
    tagid_ = std::make_shared<int64_t>(pTagid);
    dirtyFlag_[1] = true;
}

const int64_t &Tagassociations::getValueOfContentid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(contentid_)
        return *contentid_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Tagassociations::getContentid() const noexcept
{
    return contentid_;
}
void Tagassociations::setContentid(const int64_t &pContentid) noexcept
{
    contentid_ = std::make_shared<int64_t>(pContentid);
    dirtyFlag_[2] = true;
}

void Tagassociations::updateId(const uint64_t id)
{
}

const std::vector<std::string> &Tagassociations::insertColumns() noexcept
{
    static const std::vector<std::string> inCols={
        "tagid",
        "contentid"
    };
    return inCols;
}

void Tagassociations::outputArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getTagid())
        {
            binder << getValueOfTagid();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getContentid())
        {
            binder << getValueOfContentid();
        }
        else
        {
            binder << nullptr;
        }
    }
}

const std::vector<std::string> Tagassociations::updateColumns() const
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
    return ret;
}

void Tagassociations::updateArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getTagid())
        {
            binder << getValueOfTagid();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getContentid())
        {
            binder << getValueOfContentid();
        }
        else
        {
            binder << nullptr;
        }
    }
}
Json::Value Tagassociations::toJson() const
{
    Json::Value ret;
    if(getAssocid())
    {
        ret["associd"]=(Json::Int64)getValueOfAssocid();
    }
    else
    {
        ret["associd"]=Json::Value();
    }
    if(getTagid())
    {
        ret["tagid"]=(Json::Int64)getValueOfTagid();
    }
    else
    {
        ret["tagid"]=Json::Value();
    }
    if(getContentid())
    {
        ret["contentid"]=(Json::Int64)getValueOfContentid();
    }
    else
    {
        ret["contentid"]=Json::Value();
    }
    return ret;
}

Json::Value Tagassociations::toMasqueradedJson(
    const std::vector<std::string> &pMasqueradingVector) const
{
    Json::Value ret;
    if(pMasqueradingVector.size() == 3)
    {
        if(!pMasqueradingVector[0].empty())
        {
            if(getAssocid())
            {
                ret[pMasqueradingVector[0]]=(Json::Int64)getValueOfAssocid();
            }
            else
            {
                ret[pMasqueradingVector[0]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[1].empty())
        {
            if(getTagid())
            {
                ret[pMasqueradingVector[1]]=(Json::Int64)getValueOfTagid();
            }
            else
            {
                ret[pMasqueradingVector[1]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[2].empty())
        {
            if(getContentid())
            {
                ret[pMasqueradingVector[2]]=(Json::Int64)getValueOfContentid();
            }
            else
            {
                ret[pMasqueradingVector[2]]=Json::Value();
            }
        }
        return ret;
    }
    LOG_ERROR << "Masquerade failed";
    if(getAssocid())
    {
        ret["associd"]=(Json::Int64)getValueOfAssocid();
    }
    else
    {
        ret["associd"]=Json::Value();
    }
    if(getTagid())
    {
        ret["tagid"]=(Json::Int64)getValueOfTagid();
    }
    else
    {
        ret["tagid"]=Json::Value();
    }
    if(getContentid())
    {
        ret["contentid"]=(Json::Int64)getValueOfContentid();
    }
    else
    {
        ret["contentid"]=Json::Value();
    }
    return ret;
}

bool Tagassociations::validateJsonForCreation(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("associd"))
    {
        if(!validJsonOfField(0, "associd", pJson["associd"], err, true))
            return false;
    }
    if(pJson.isMember("tagid"))
    {
        if(!validJsonOfField(1, "tagid", pJson["tagid"], err, true))
            return false;
    }
    else
    {
        err="The tagid column cannot be null";
        return false;
    }
    if(pJson.isMember("contentid"))
    {
        if(!validJsonOfField(2, "contentid", pJson["contentid"], err, true))
            return false;
    }
    else
    {
        err="The contentid column cannot be null";
        return false;
    }
    return true;
}
bool Tagassociations::validateMasqueradedJsonForCreation(const Json::Value &pJson,
                                                         const std::vector<std::string> &pMasqueradingVector,
                                                         std::string &err)
{
    if(pMasqueradingVector.size() != 3)
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
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Tagassociations::validateJsonForUpdate(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("associd"))
    {
        if(!validJsonOfField(0, "associd", pJson["associd"], err, false))
            return false;
    }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
    if(pJson.isMember("tagid"))
    {
        if(!validJsonOfField(1, "tagid", pJson["tagid"], err, false))
            return false;
    }
    if(pJson.isMember("contentid"))
    {
        if(!validJsonOfField(2, "contentid", pJson["contentid"], err, false))
            return false;
    }
    return true;
}
bool Tagassociations::validateMasqueradedJsonForUpdate(const Json::Value &pJson,
                                                       const std::vector<std::string> &pMasqueradingVector,
                                                       std::string &err)
{
    if(pMasqueradingVector.size() != 3)
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
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Tagassociations::validJsonOfField(size_t index,
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
            if(!pJson.isInt64())
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
