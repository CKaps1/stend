/**
 *
 *  Comments.cc
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#include "Comments.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
using namespace drogon::orm;
using namespace drogon_model::stend;

const std::string Comments::Cols::_commentid = "commentid";
const std::string Comments::Cols::_userid = "userid";
const std::string Comments::Cols::_contentid = "contentid";
const std::string Comments::Cols::_upvotes = "upvotes";
const std::string Comments::Cols::_downvotes = "downvotes";
const std::string Comments::Cols::_comment = "comment";
const std::string Comments::primaryKeyName = "commentid";
const bool Comments::hasPrimaryKey = true;
const std::string Comments::tableName = "comments";

const std::vector<typename Comments::MetaData> Comments::metaData_={
{"commentid","int64_t","bigint",8,1,1,1},
{"userid","int64_t","bigint",8,0,0,1},
{"contentid","int64_t","bigint",8,0,0,1},
{"upvotes","int32_t","integer",4,0,0,1},
{"downvotes","int32_t","integer",4,0,0,1},
{"comment","std::string","text",0,0,0,1}
};
const std::string &Comments::getColumnName(size_t index) noexcept(false)
{
    assert(index < metaData_.size());
    return metaData_[index].colName_;
}
Comments::Comments(const Row &r, const ssize_t indexOffset) noexcept
{
    if(indexOffset < 0)
    {
        if(!r["commentid"].isNull())
        {
            commentid_=std::make_shared<int64_t>(r["commentid"].as<int64_t>());
        }
        if(!r["userid"].isNull())
        {
            userid_=std::make_shared<int64_t>(r["userid"].as<int64_t>());
        }
        if(!r["contentid"].isNull())
        {
            contentid_=std::make_shared<int64_t>(r["contentid"].as<int64_t>());
        }
        if(!r["upvotes"].isNull())
        {
            upvotes_=std::make_shared<int32_t>(r["upvotes"].as<int32_t>());
        }
        if(!r["downvotes"].isNull())
        {
            downvotes_=std::make_shared<int32_t>(r["downvotes"].as<int32_t>());
        }
        if(!r["comment"].isNull())
        {
            comment_=std::make_shared<std::string>(r["comment"].as<std::string>());
        }
    }
    else
    {
        size_t offset = (size_t)indexOffset;
        if(offset + 6 > r.size())
        {
            LOG_FATAL << "Invalid SQL result for this model";
            return;
        }
        size_t index;
        index = offset + 0;
        if(!r[index].isNull())
        {
            commentid_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
        index = offset + 1;
        if(!r[index].isNull())
        {
            userid_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
        index = offset + 2;
        if(!r[index].isNull())
        {
            contentid_=std::make_shared<int64_t>(r[index].as<int64_t>());
        }
        index = offset + 3;
        if(!r[index].isNull())
        {
            upvotes_=std::make_shared<int32_t>(r[index].as<int32_t>());
        }
        index = offset + 4;
        if(!r[index].isNull())
        {
            downvotes_=std::make_shared<int32_t>(r[index].as<int32_t>());
        }
        index = offset + 5;
        if(!r[index].isNull())
        {
            comment_=std::make_shared<std::string>(r[index].as<std::string>());
        }
    }

}

Comments::Comments(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 6)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        dirtyFlag_[0] = true;
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            commentid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[0]].asInt64());
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
            contentid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[2]].asInt64());
        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            upvotes_=std::make_shared<int32_t>((int32_t)pJson[pMasqueradingVector[3]].asInt64());
        }
    }
    if(!pMasqueradingVector[4].empty() && pJson.isMember(pMasqueradingVector[4]))
    {
        dirtyFlag_[4] = true;
        if(!pJson[pMasqueradingVector[4]].isNull())
        {
            downvotes_=std::make_shared<int32_t>((int32_t)pJson[pMasqueradingVector[4]].asInt64());
        }
    }
    if(!pMasqueradingVector[5].empty() && pJson.isMember(pMasqueradingVector[5]))
    {
        dirtyFlag_[5] = true;
        if(!pJson[pMasqueradingVector[5]].isNull())
        {
            comment_=std::make_shared<std::string>(pJson[pMasqueradingVector[5]].asString());
        }
    }
}

Comments::Comments(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("commentid"))
    {
        dirtyFlag_[0]=true;
        if(!pJson["commentid"].isNull())
        {
            commentid_=std::make_shared<int64_t>((int64_t)pJson["commentid"].asInt64());
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
    if(pJson.isMember("contentid"))
    {
        dirtyFlag_[2]=true;
        if(!pJson["contentid"].isNull())
        {
            contentid_=std::make_shared<int64_t>((int64_t)pJson["contentid"].asInt64());
        }
    }
    if(pJson.isMember("upvotes"))
    {
        dirtyFlag_[3]=true;
        if(!pJson["upvotes"].isNull())
        {
            upvotes_=std::make_shared<int32_t>((int32_t)pJson["upvotes"].asInt64());
        }
    }
    if(pJson.isMember("downvotes"))
    {
        dirtyFlag_[4]=true;
        if(!pJson["downvotes"].isNull())
        {
            downvotes_=std::make_shared<int32_t>((int32_t)pJson["downvotes"].asInt64());
        }
    }
    if(pJson.isMember("comment"))
    {
        dirtyFlag_[5]=true;
        if(!pJson["comment"].isNull())
        {
            comment_=std::make_shared<std::string>(pJson["comment"].asString());
        }
    }
}

void Comments::updateByMasqueradedJson(const Json::Value &pJson,
                                            const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 6)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            commentid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[0]].asInt64());
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
            contentid_=std::make_shared<int64_t>((int64_t)pJson[pMasqueradingVector[2]].asInt64());
        }
    }
    if(!pMasqueradingVector[3].empty() && pJson.isMember(pMasqueradingVector[3]))
    {
        dirtyFlag_[3] = true;
        if(!pJson[pMasqueradingVector[3]].isNull())
        {
            upvotes_=std::make_shared<int32_t>((int32_t)pJson[pMasqueradingVector[3]].asInt64());
        }
    }
    if(!pMasqueradingVector[4].empty() && pJson.isMember(pMasqueradingVector[4]))
    {
        dirtyFlag_[4] = true;
        if(!pJson[pMasqueradingVector[4]].isNull())
        {
            downvotes_=std::make_shared<int32_t>((int32_t)pJson[pMasqueradingVector[4]].asInt64());
        }
    }
    if(!pMasqueradingVector[5].empty() && pJson.isMember(pMasqueradingVector[5]))
    {
        dirtyFlag_[5] = true;
        if(!pJson[pMasqueradingVector[5]].isNull())
        {
            comment_=std::make_shared<std::string>(pJson[pMasqueradingVector[5]].asString());
        }
    }
}

void Comments::updateByJson(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("commentid"))
    {
        if(!pJson["commentid"].isNull())
        {
            commentid_=std::make_shared<int64_t>((int64_t)pJson["commentid"].asInt64());
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
    if(pJson.isMember("contentid"))
    {
        dirtyFlag_[2] = true;
        if(!pJson["contentid"].isNull())
        {
            contentid_=std::make_shared<int64_t>((int64_t)pJson["contentid"].asInt64());
        }
    }
    if(pJson.isMember("upvotes"))
    {
        dirtyFlag_[3] = true;
        if(!pJson["upvotes"].isNull())
        {
            upvotes_=std::make_shared<int32_t>((int32_t)pJson["upvotes"].asInt64());
        }
    }
    if(pJson.isMember("downvotes"))
    {
        dirtyFlag_[4] = true;
        if(!pJson["downvotes"].isNull())
        {
            downvotes_=std::make_shared<int32_t>((int32_t)pJson["downvotes"].asInt64());
        }
    }
    if(pJson.isMember("comment"))
    {
        dirtyFlag_[5] = true;
        if(!pJson["comment"].isNull())
        {
            comment_=std::make_shared<std::string>(pJson["comment"].asString());
        }
    }
}

const int64_t &Comments::getValueOfCommentid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(commentid_)
        return *commentid_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Comments::getCommentid() const noexcept
{
    return commentid_;
}
void Comments::setCommentid(const int64_t &pCommentid) noexcept
{
    commentid_ = std::make_shared<int64_t>(pCommentid);
    dirtyFlag_[0] = true;
}
const typename Comments::PrimaryKeyType & Comments::getPrimaryKey() const
{
    assert(commentid_);
    return *commentid_;
}

const int64_t &Comments::getValueOfUserid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(userid_)
        return *userid_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Comments::getUserid() const noexcept
{
    return userid_;
}
void Comments::setUserid(const int64_t &pUserid) noexcept
{
    userid_ = std::make_shared<int64_t>(pUserid);
    dirtyFlag_[1] = true;
}

const int64_t &Comments::getValueOfContentid() const noexcept
{
    const static int64_t defaultValue = int64_t();
    if(contentid_)
        return *contentid_;
    return defaultValue;
}
const std::shared_ptr<int64_t> &Comments::getContentid() const noexcept
{
    return contentid_;
}
void Comments::setContentid(const int64_t &pContentid) noexcept
{
    contentid_ = std::make_shared<int64_t>(pContentid);
    dirtyFlag_[2] = true;
}

const int32_t &Comments::getValueOfUpvotes() const noexcept
{
    const static int32_t defaultValue = int32_t();
    if(upvotes_)
        return *upvotes_;
    return defaultValue;
}
const std::shared_ptr<int32_t> &Comments::getUpvotes() const noexcept
{
    return upvotes_;
}
void Comments::setUpvotes(const int32_t &pUpvotes) noexcept
{
    upvotes_ = std::make_shared<int32_t>(pUpvotes);
    dirtyFlag_[3] = true;
}

const int32_t &Comments::getValueOfDownvotes() const noexcept
{
    const static int32_t defaultValue = int32_t();
    if(downvotes_)
        return *downvotes_;
    return defaultValue;
}
const std::shared_ptr<int32_t> &Comments::getDownvotes() const noexcept
{
    return downvotes_;
}
void Comments::setDownvotes(const int32_t &pDownvotes) noexcept
{
    downvotes_ = std::make_shared<int32_t>(pDownvotes);
    dirtyFlag_[4] = true;
}

const std::string &Comments::getValueOfComment() const noexcept
{
    const static std::string defaultValue = std::string();
    if(comment_)
        return *comment_;
    return defaultValue;
}
const std::shared_ptr<std::string> &Comments::getComment() const noexcept
{
    return comment_;
}
void Comments::setComment(const std::string &pComment) noexcept
{
    comment_ = std::make_shared<std::string>(pComment);
    dirtyFlag_[5] = true;
}
void Comments::setComment(std::string &&pComment) noexcept
{
    comment_ = std::make_shared<std::string>(std::move(pComment));
    dirtyFlag_[5] = true;
}

void Comments::updateId(const uint64_t id)
{
}

const std::vector<std::string> &Comments::insertColumns() noexcept
{
    static const std::vector<std::string> inCols={
        "userid",
        "contentid",
        "upvotes",
        "downvotes",
        "comment"
    };
    return inCols;
}

void Comments::outputArgs(drogon::orm::internal::SqlBinder &binder) const
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
        if(getContentid())
        {
            binder << getValueOfContentid();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getUpvotes())
        {
            binder << getValueOfUpvotes();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[4])
    {
        if(getDownvotes())
        {
            binder << getValueOfDownvotes();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[5])
    {
        if(getComment())
        {
            binder << getValueOfComment();
        }
        else
        {
            binder << nullptr;
        }
    }
}

const std::vector<std::string> Comments::updateColumns() const
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
    if(dirtyFlag_[5])
    {
        ret.push_back(getColumnName(5));
    }
    return ret;
}

void Comments::updateArgs(drogon::orm::internal::SqlBinder &binder) const
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
        if(getContentid())
        {
            binder << getValueOfContentid();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[3])
    {
        if(getUpvotes())
        {
            binder << getValueOfUpvotes();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[4])
    {
        if(getDownvotes())
        {
            binder << getValueOfDownvotes();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[5])
    {
        if(getComment())
        {
            binder << getValueOfComment();
        }
        else
        {
            binder << nullptr;
        }
    }
}
Json::Value Comments::toJson() const
{
    Json::Value ret;
    if(getCommentid())
    {
        ret["commentid"]=(Json::Int64)getValueOfCommentid();
    }
    else
    {
        ret["commentid"]=Json::Value();
    }
    if(getUserid())
    {
        ret["userid"]=(Json::Int64)getValueOfUserid();
    }
    else
    {
        ret["userid"]=Json::Value();
    }
    if(getContentid())
    {
        ret["contentid"]=(Json::Int64)getValueOfContentid();
    }
    else
    {
        ret["contentid"]=Json::Value();
    }
    if(getUpvotes())
    {
        ret["upvotes"]=getValueOfUpvotes();
    }
    else
    {
        ret["upvotes"]=Json::Value();
    }
    if(getDownvotes())
    {
        ret["downvotes"]=getValueOfDownvotes();
    }
    else
    {
        ret["downvotes"]=Json::Value();
    }
    if(getComment())
    {
        ret["comment"]=getValueOfComment();
    }
    else
    {
        ret["comment"]=Json::Value();
    }
    return ret;
}

Json::Value Comments::toMasqueradedJson(
    const std::vector<std::string> &pMasqueradingVector) const
{
    Json::Value ret;
    if(pMasqueradingVector.size() == 6)
    {
        if(!pMasqueradingVector[0].empty())
        {
            if(getCommentid())
            {
                ret[pMasqueradingVector[0]]=(Json::Int64)getValueOfCommentid();
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
            if(getContentid())
            {
                ret[pMasqueradingVector[2]]=(Json::Int64)getValueOfContentid();
            }
            else
            {
                ret[pMasqueradingVector[2]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[3].empty())
        {
            if(getUpvotes())
            {
                ret[pMasqueradingVector[3]]=getValueOfUpvotes();
            }
            else
            {
                ret[pMasqueradingVector[3]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[4].empty())
        {
            if(getDownvotes())
            {
                ret[pMasqueradingVector[4]]=getValueOfDownvotes();
            }
            else
            {
                ret[pMasqueradingVector[4]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[5].empty())
        {
            if(getComment())
            {
                ret[pMasqueradingVector[5]]=getValueOfComment();
            }
            else
            {
                ret[pMasqueradingVector[5]]=Json::Value();
            }
        }
        return ret;
    }
    LOG_ERROR << "Masquerade failed";
    if(getCommentid())
    {
        ret["commentid"]=(Json::Int64)getValueOfCommentid();
    }
    else
    {
        ret["commentid"]=Json::Value();
    }
    if(getUserid())
    {
        ret["userid"]=(Json::Int64)getValueOfUserid();
    }
    else
    {
        ret["userid"]=Json::Value();
    }
    if(getContentid())
    {
        ret["contentid"]=(Json::Int64)getValueOfContentid();
    }
    else
    {
        ret["contentid"]=Json::Value();
    }
    if(getUpvotes())
    {
        ret["upvotes"]=getValueOfUpvotes();
    }
    else
    {
        ret["upvotes"]=Json::Value();
    }
    if(getDownvotes())
    {
        ret["downvotes"]=getValueOfDownvotes();
    }
    else
    {
        ret["downvotes"]=Json::Value();
    }
    if(getComment())
    {
        ret["comment"]=getValueOfComment();
    }
    else
    {
        ret["comment"]=Json::Value();
    }
    return ret;
}

bool Comments::validateJsonForCreation(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("commentid"))
    {
        if(!validJsonOfField(0, "commentid", pJson["commentid"], err, true))
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
    if(pJson.isMember("upvotes"))
    {
        if(!validJsonOfField(3, "upvotes", pJson["upvotes"], err, true))
            return false;
    }
    else
    {
        err="The upvotes column cannot be null";
        return false;
    }
    if(pJson.isMember("downvotes"))
    {
        if(!validJsonOfField(4, "downvotes", pJson["downvotes"], err, true))
            return false;
    }
    else
    {
        err="The downvotes column cannot be null";
        return false;
    }
    if(pJson.isMember("comment"))
    {
        if(!validJsonOfField(5, "comment", pJson["comment"], err, true))
            return false;
    }
    else
    {
        err="The comment column cannot be null";
        return false;
    }
    return true;
}
bool Comments::validateMasqueradedJsonForCreation(const Json::Value &pJson,
                                                  const std::vector<std::string> &pMasqueradingVector,
                                                  std::string &err)
{
    if(pMasqueradingVector.size() != 6)
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
      if(!pMasqueradingVector[5].empty())
      {
          if(pJson.isMember(pMasqueradingVector[5]))
          {
              if(!validJsonOfField(5, pMasqueradingVector[5], pJson[pMasqueradingVector[5]], err, true))
                  return false;
          }
        else
        {
            err="The " + pMasqueradingVector[5] + " column cannot be null";
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
bool Comments::validateJsonForUpdate(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("commentid"))
    {
        if(!validJsonOfField(0, "commentid", pJson["commentid"], err, false))
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
    if(pJson.isMember("contentid"))
    {
        if(!validJsonOfField(2, "contentid", pJson["contentid"], err, false))
            return false;
    }
    if(pJson.isMember("upvotes"))
    {
        if(!validJsonOfField(3, "upvotes", pJson["upvotes"], err, false))
            return false;
    }
    if(pJson.isMember("downvotes"))
    {
        if(!validJsonOfField(4, "downvotes", pJson["downvotes"], err, false))
            return false;
    }
    if(pJson.isMember("comment"))
    {
        if(!validJsonOfField(5, "comment", pJson["comment"], err, false))
            return false;
    }
    return true;
}
bool Comments::validateMasqueradedJsonForUpdate(const Json::Value &pJson,
                                                const std::vector<std::string> &pMasqueradingVector,
                                                std::string &err)
{
    if(pMasqueradingVector.size() != 6)
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
      if(!pMasqueradingVector[5].empty() && pJson.isMember(pMasqueradingVector[5]))
      {
          if(!validJsonOfField(5, pMasqueradingVector[5], pJson[pMasqueradingVector[5]], err, false))
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
bool Comments::validJsonOfField(size_t index,
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
        case 3:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(!pJson.isInt())
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
            if(!pJson.isInt())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 5:
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
