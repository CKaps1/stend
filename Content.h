/**
 *
 *  Content.h
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#pragma once
#include <drogon/orm/Result.h>
#include <drogon/orm/Row.h>
#include <drogon/orm/Field.h>
#include <drogon/orm/SqlBinder.h>
#include <drogon/orm/Mapper.h>
#ifdef __cpp_impl_coroutine
#include <drogon/orm/CoroMapper.h>
#endif
#include <trantor/utils/Date.h>
#include <trantor/utils/Logger.h>
#include <json/json.h>
#include <string>
#include <memory>
#include <vector>
#include <tuple>
#include <stdint.h>
#include <iostream>

namespace drogon
{
namespace orm
{
class DbClient;
using DbClientPtr = std::shared_ptr<DbClient>;
}
}
namespace drogon_model
{
namespace stend
{

class Content
{
  public:
    struct Cols
    {
        static const std::string _contentid;
        static const std::string _filename;
        static const std::string _owner;
        static const std::string _displayname;
        static const std::string _caption;
        static const std::string _likes;
        static const std::string _dislikes;
        static const std::string _views;
        static const std::string _flags;
        static const std::string _displayname_tsvector;
        static const std::string _caption_tsvector;
        static const std::string _ispublic;
        static const std::string _cancomment;
    };

    const static int primaryKeyNumber;
    const static std::string tableName;
    const static bool hasPrimaryKey;
    const static std::string primaryKeyName;
    using PrimaryKeyType = int64_t;
    const PrimaryKeyType &getPrimaryKey() const;

    /**
     * @brief constructor
     * @param r One row of records in the SQL query result.
     * @param indexOffset Set the offset to -1 to access all columns by column names,
     * otherwise access all columns by offsets.
     * @note If the SQL is not a style of 'select * from table_name ...' (select all
     * columns by an asterisk), please set the offset to -1.
     */
    explicit Content(const drogon::orm::Row &r, const ssize_t indexOffset = 0) noexcept;

    /**
     * @brief constructor
     * @param pJson The json object to construct a new instance.
     */
    explicit Content(const Json::Value &pJson) noexcept(false);

    /**
     * @brief constructor
     * @param pJson The json object to construct a new instance.
     * @param pMasqueradingVector The aliases of table columns.
     */
    Content(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false);

    Content() = default;

    void updateByJson(const Json::Value &pJson) noexcept(false);
    void updateByMasqueradedJson(const Json::Value &pJson,
                                 const std::vector<std::string> &pMasqueradingVector) noexcept(false);
    static bool validateJsonForCreation(const Json::Value &pJson, std::string &err);
    static bool validateMasqueradedJsonForCreation(const Json::Value &,
                                                const std::vector<std::string> &pMasqueradingVector,
                                                    std::string &err);
    static bool validateJsonForUpdate(const Json::Value &pJson, std::string &err);
    static bool validateMasqueradedJsonForUpdate(const Json::Value &,
                                          const std::vector<std::string> &pMasqueradingVector,
                                          std::string &err);
    static bool validJsonOfField(size_t index,
                          const std::string &fieldName,
                          const Json::Value &pJson,
                          std::string &err,
                          bool isForCreation);

    /**  For column contentid  */
    ///Get the value of the column contentid, returns the default value if the column is null
    const int64_t &getValueOfContentid() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int64_t> &getContentid() const noexcept;
    ///Set the value of the column contentid
    void setContentid(const int64_t &pContentid) noexcept;

    /**  For column filename  */
    ///Get the value of the column filename, returns the default value if the column is null
    const std::string &getValueOfFilename() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getFilename() const noexcept;
    ///Set the value of the column filename
    void setFilename(const std::string &pFilename) noexcept;
    void setFilename(std::string &&pFilename) noexcept;

    /**  For column owner  */
    ///Get the value of the column owner, returns the default value if the column is null
    const int64_t &getValueOfOwner() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int64_t> &getOwner() const noexcept;
    ///Set the value of the column owner
    void setOwner(const int64_t &pOwner) noexcept;

    /**  For column displayname  */
    ///Get the value of the column displayname, returns the default value if the column is null
    const std::string &getValueOfDisplayname() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getDisplayname() const noexcept;
    ///Set the value of the column displayname
    void setDisplayname(const std::string &pDisplayname) noexcept;
    void setDisplayname(std::string &&pDisplayname) noexcept;
    void setDisplaynameToNull() noexcept;

    /**  For column caption  */
    ///Get the value of the column caption, returns the default value if the column is null
    const std::string &getValueOfCaption() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getCaption() const noexcept;
    ///Set the value of the column caption
    void setCaption(const std::string &pCaption) noexcept;
    void setCaption(std::string &&pCaption) noexcept;
    void setCaptionToNull() noexcept;

    /**  For column likes  */
    ///Get the value of the column likes, returns the default value if the column is null
    const int64_t &getValueOfLikes() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int64_t> &getLikes() const noexcept;
    ///Set the value of the column likes
    void setLikes(const int64_t &pLikes) noexcept;

    /**  For column dislikes  */
    ///Get the value of the column dislikes, returns the default value if the column is null
    const int64_t &getValueOfDislikes() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int64_t> &getDislikes() const noexcept;
    ///Set the value of the column dislikes
    void setDislikes(const int64_t &pDislikes) noexcept;

    /**  For column views  */
    ///Get the value of the column views, returns the default value if the column is null
    const int64_t &getValueOfViews() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int64_t> &getViews() const noexcept;
    ///Set the value of the column views
    void setViews(const int64_t &pViews) noexcept;

    /**  For column flags  */
    ///Get the value of the column flags, returns the default value if the column is null
    const int64_t &getValueOfFlags() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int64_t> &getFlags() const noexcept;
    ///Set the value of the column flags
    void setFlags(const int64_t &pFlags) noexcept;

    /**  For column displayname_tsvector  */
    ///Get the value of the column displayname_tsvector, returns the default value if the column is null
    const std::string &getValueOfDisplaynameTsvector() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getDisplaynameTsvector() const noexcept;
    ///Set the value of the column displayname_tsvector
    void setDisplaynameTsvector(const std::string &pDisplaynameTsvector) noexcept;
    void setDisplaynameTsvector(std::string &&pDisplaynameTsvector) noexcept;
    void setDisplaynameTsvectorToNull() noexcept;

    /**  For column caption_tsvector  */
    ///Get the value of the column caption_tsvector, returns the default value if the column is null
    const std::string &getValueOfCaptionTsvector() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getCaptionTsvector() const noexcept;
    ///Set the value of the column caption_tsvector
    void setCaptionTsvector(const std::string &pCaptionTsvector) noexcept;
    void setCaptionTsvector(std::string &&pCaptionTsvector) noexcept;
    void setCaptionTsvectorToNull() noexcept;

    /**  For column ispublic  */
    ///Get the value of the column ispublic, returns the default value if the column is null
    const std::string &getValueOfIspublic() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getIspublic() const noexcept;
    ///Set the value of the column ispublic
    void setIspublic(const std::string &pIspublic) noexcept;
    void setIspublic(std::string &&pIspublic) noexcept;
    void setIspublicToNull() noexcept;

    /**  For column cancomment  */
    ///Get the value of the column cancomment, returns the default value if the column is null
    const std::string &getValueOfCancomment() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getCancomment() const noexcept;
    ///Set the value of the column cancomment
    void setCancomment(const std::string &pCancomment) noexcept;
    void setCancomment(std::string &&pCancomment) noexcept;
    void setCancommentToNull() noexcept;


    static size_t getColumnNumber() noexcept {  return 13;  }
    static const std::string &getColumnName(size_t index) noexcept(false);

    Json::Value toJson() const;
    Json::Value toMasqueradedJson(const std::vector<std::string> &pMasqueradingVector) const;
    /// Relationship interfaces
  private:
    friend drogon::orm::Mapper<Content>;
#ifdef __cpp_impl_coroutine
    friend drogon::orm::CoroMapper<Content>;
#endif
    static const std::vector<std::string> &insertColumns() noexcept;
    void outputArgs(drogon::orm::internal::SqlBinder &binder) const;
    const std::vector<std::string> updateColumns() const;
    void updateArgs(drogon::orm::internal::SqlBinder &binder) const;
    ///For mysql or sqlite3
    void updateId(const uint64_t id);
    std::shared_ptr<int64_t> contentid_;
    std::shared_ptr<std::string> filename_;
    std::shared_ptr<int64_t> owner_;
    std::shared_ptr<std::string> displayname_;
    std::shared_ptr<std::string> caption_;
    std::shared_ptr<int64_t> likes_;
    std::shared_ptr<int64_t> dislikes_;
    std::shared_ptr<int64_t> views_;
    std::shared_ptr<int64_t> flags_;
    std::shared_ptr<std::string> displaynameTsvector_;
    std::shared_ptr<std::string> captionTsvector_;
    std::shared_ptr<std::string> ispublic_;
    std::shared_ptr<std::string> cancomment_;
    struct MetaData
    {
        const std::string colName_;
        const std::string colType_;
        const std::string colDatabaseType_;
        const ssize_t colLength_;
        const bool isAutoVal_;
        const bool isPrimaryKey_;
        const bool notNull_;
    };
    static const std::vector<MetaData> metaData_;
    bool dirtyFlag_[13]={ false };
  public:
    static const std::string &sqlForFindingByPrimaryKey()
    {
        static const std::string sql="select * from " + tableName + " where contentid = $1";
        return sql;
    }

    static const std::string &sqlForDeletingByPrimaryKey()
    {
        static const std::string sql="delete from " + tableName + " where contentid = $1";
        return sql;
    }
    std::string sqlForInserting(bool &needSelection) const
    {
        std::string sql="insert into " + tableName + " (";
        size_t parametersCount = 0;
        needSelection = false;
            sql += "contentid,";
            ++parametersCount;
        if(dirtyFlag_[1])
        {
            sql += "filename,";
            ++parametersCount;
        }
        if(dirtyFlag_[2])
        {
            sql += "owner,";
            ++parametersCount;
        }
        if(dirtyFlag_[3])
        {
            sql += "displayname,";
            ++parametersCount;
        }
        if(dirtyFlag_[4])
        {
            sql += "caption,";
            ++parametersCount;
        }
        if(dirtyFlag_[5])
        {
            sql += "likes,";
            ++parametersCount;
        }
        if(dirtyFlag_[6])
        {
            sql += "dislikes,";
            ++parametersCount;
        }
        if(dirtyFlag_[7])
        {
            sql += "views,";
            ++parametersCount;
        }
        if(dirtyFlag_[8])
        {
            sql += "flags,";
            ++parametersCount;
        }
        if(dirtyFlag_[9])
        {
            sql += "displayname_tsvector,";
            ++parametersCount;
        }
        if(dirtyFlag_[10])
        {
            sql += "caption_tsvector,";
            ++parametersCount;
        }
        if(dirtyFlag_[11])
        {
            sql += "ispublic,";
            ++parametersCount;
        }
        if(dirtyFlag_[12])
        {
            sql += "cancomment,";
            ++parametersCount;
        }
        needSelection=true;
        if(parametersCount > 0)
        {
            sql[sql.length()-1]=')';
            sql += " values (";
        }
        else
            sql += ") values (";

        int placeholder=1;
        char placeholderStr[64];
        size_t n=0;
        sql +="default,";
        if(dirtyFlag_[1])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[2])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[3])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[4])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[5])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[6])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[7])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[8])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[9])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[10])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[11])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[12])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(parametersCount > 0)
        {
            sql.resize(sql.length() - 1);
        }
        if(needSelection)
        {
            sql.append(") returning *");
        }
        else
        {
            sql.append(1, ')');
        }
        LOG_TRACE << sql;
        return sql;
    }
};
} // namespace stend
} // namespace drogon_model