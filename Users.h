/**
 *
 *  Users.h
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

class Users
{
  public:
    struct Cols
    {
        static const std::string _userid;
        static const std::string _email;
        static const std::string _emailnonce;
        static const std::string _emailsearchable;
        static const std::string _lastlogin;
        static const std::string _username;
        static const std::string _passwordhash;
        static const std::string _passwordsalt;
        static const std::string _gender;
        static const std::string _profilepicture;
        static const std::string _profilepictureurl;
        static const std::string _birthyear;
        static const std::string _permanentlocation;
        static const std::string _permanentlocationnonce;
        static const std::string _displayname;
        static const std::string _incorrect_password_attempts;
        static const std::string _incorrect_password_attempt_date;
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
    explicit Users(const drogon::orm::Row &r, const ssize_t indexOffset = 0) noexcept;

    /**
     * @brief constructor
     * @param pJson The json object to construct a new instance.
     */
    explicit Users(const Json::Value &pJson) noexcept(false);

    /**
     * @brief constructor
     * @param pJson The json object to construct a new instance.
     * @param pMasqueradingVector The aliases of table columns.
     */
    Users(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false);

    Users() = default;

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

    /**  For column userid  */
    ///Get the value of the column userid, returns the default value if the column is null
    const int64_t &getValueOfUserid() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int64_t> &getUserid() const noexcept;
    ///Set the value of the column userid
    void setUserid(const int64_t &pUserid) noexcept;

    /**  For column email  */
    ///Get the value of the column email, returns the default value if the column is null
    const std::vector<char> &getValueOfEmail() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfEmailAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getEmail() const noexcept;
    ///Set the value of the column email
    void setEmail(const std::vector<char> &pEmail) noexcept;
    void setEmail(const std::string &pEmail) noexcept;

    /**  For column emailnonce  */
    ///Get the value of the column emailnonce, returns the default value if the column is null
    const std::vector<char> &getValueOfEmailnonce() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfEmailnonceAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getEmailnonce() const noexcept;
    ///Set the value of the column emailnonce
    void setEmailnonce(const std::vector<char> &pEmailnonce) noexcept;
    void setEmailnonce(const std::string &pEmailnonce) noexcept;

    /**  For column emailsearchable  */
    ///Get the value of the column emailsearchable, returns the default value if the column is null
    const std::vector<char> &getValueOfEmailsearchable() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfEmailsearchableAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getEmailsearchable() const noexcept;
    ///Set the value of the column emailsearchable
    void setEmailsearchable(const std::vector<char> &pEmailsearchable) noexcept;
    void setEmailsearchable(const std::string &pEmailsearchable) noexcept;

    /**  For column lastlogin  */
    ///Get the value of the column lastlogin, returns the default value if the column is null
    const ::trantor::Date &getValueOfLastlogin() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<::trantor::Date> &getLastlogin() const noexcept;
    ///Set the value of the column lastlogin
    void setLastlogin(const ::trantor::Date &pLastlogin) noexcept;
    void setLastloginToNull() noexcept;

    /**  For column username  */
    ///Get the value of the column username, returns the default value if the column is null
    const std::string &getValueOfUsername() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getUsername() const noexcept;
    ///Set the value of the column username
    void setUsername(const std::string &pUsername) noexcept;
    void setUsername(std::string &&pUsername) noexcept;

    /**  For column passwordhash  */
    ///Get the value of the column passwordhash, returns the default value if the column is null
    const std::vector<char> &getValueOfPasswordhash() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfPasswordhashAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getPasswordhash() const noexcept;
    ///Set the value of the column passwordhash
    void setPasswordhash(const std::vector<char> &pPasswordhash) noexcept;
    void setPasswordhash(const std::string &pPasswordhash) noexcept;

    /**  For column passwordsalt  */
    ///Get the value of the column passwordsalt, returns the default value if the column is null
    const std::vector<char> &getValueOfPasswordsalt() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfPasswordsaltAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getPasswordsalt() const noexcept;
    ///Set the value of the column passwordsalt
    void setPasswordsalt(const std::vector<char> &pPasswordsalt) noexcept;
    void setPasswordsalt(const std::string &pPasswordsalt) noexcept;

    /**  For column gender  */
    ///Get the value of the column gender, returns the default value if the column is null
    const std::string &getValueOfGender() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getGender() const noexcept;
    ///Set the value of the column gender
    void setGender(const std::string &pGender) noexcept;
    void setGender(std::string &&pGender) noexcept;
    void setGenderToNull() noexcept;

    /**  For column profilepicture  */
    ///Get the value of the column profilepicture, returns the default value if the column is null
    const std::vector<char> &getValueOfProfilepicture() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfProfilepictureAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getProfilepicture() const noexcept;
    ///Set the value of the column profilepicture
    void setProfilepicture(const std::vector<char> &pProfilepicture) noexcept;
    void setProfilepicture(const std::string &pProfilepicture) noexcept;
    void setProfilepictureToNull() noexcept;

    /**  For column profilepictureurl  */
    ///Get the value of the column profilepictureurl, returns the default value if the column is null
    const std::string &getValueOfProfilepictureurl() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getProfilepictureurl() const noexcept;
    ///Set the value of the column profilepictureurl
    void setProfilepictureurl(const std::string &pProfilepictureurl) noexcept;
    void setProfilepictureurl(std::string &&pProfilepictureurl) noexcept;
    void setProfilepictureurlToNull() noexcept;

    /**  For column birthyear  */
    ///Get the value of the column birthyear, returns the default value if the column is null
    const int32_t &getValueOfBirthyear() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int32_t> &getBirthyear() const noexcept;
    ///Set the value of the column birthyear
    void setBirthyear(const int32_t &pBirthyear) noexcept;
    void setBirthyearToNull() noexcept;

    /**  For column permanentlocation  */
    ///Get the value of the column permanentlocation, returns the default value if the column is null
    const std::vector<char> &getValueOfPermanentlocation() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfPermanentlocationAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getPermanentlocation() const noexcept;
    ///Set the value of the column permanentlocation
    void setPermanentlocation(const std::vector<char> &pPermanentlocation) noexcept;
    void setPermanentlocation(const std::string &pPermanentlocation) noexcept;
    void setPermanentlocationToNull() noexcept;

    /**  For column permanentlocationnonce  */
    ///Get the value of the column permanentlocationnonce, returns the default value if the column is null
    const std::vector<char> &getValueOfPermanentlocationnonce() const noexcept;
    ///Return the column value by std::string with binary data
    std::string getValueOfPermanentlocationnonceAsString() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::vector<char>> &getPermanentlocationnonce() const noexcept;
    ///Set the value of the column permanentlocationnonce
    void setPermanentlocationnonce(const std::vector<char> &pPermanentlocationnonce) noexcept;
    void setPermanentlocationnonce(const std::string &pPermanentlocationnonce) noexcept;
    void setPermanentlocationnonceToNull() noexcept;

    /**  For column displayname  */
    ///Get the value of the column displayname, returns the default value if the column is null
    const std::string &getValueOfDisplayname() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getDisplayname() const noexcept;
    ///Set the value of the column displayname
    void setDisplayname(const std::string &pDisplayname) noexcept;
    void setDisplayname(std::string &&pDisplayname) noexcept;
    void setDisplaynameToNull() noexcept;

    /**  For column incorrect_password_attempts  */
    ///Get the value of the column incorrect_password_attempts, returns the default value if the column is null
    const int32_t &getValueOfIncorrectPasswordAttempts() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<int32_t> &getIncorrectPasswordAttempts() const noexcept;
    ///Set the value of the column incorrect_password_attempts
    void setIncorrectPasswordAttempts(const int32_t &pIncorrectPasswordAttempts) noexcept;
    void setIncorrectPasswordAttemptsToNull() noexcept;

    /**  For column incorrect_password_attempt_date  */
    ///Get the value of the column incorrect_password_attempt_date, returns the default value if the column is null
    const ::trantor::Date &getValueOfIncorrectPasswordAttemptDate() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<::trantor::Date> &getIncorrectPasswordAttemptDate() const noexcept;
    ///Set the value of the column incorrect_password_attempt_date
    void setIncorrectPasswordAttemptDate(const ::trantor::Date &pIncorrectPasswordAttemptDate) noexcept;
    void setIncorrectPasswordAttemptDateToNull() noexcept;


    static size_t getColumnNumber() noexcept {  return 17;  }
    static const std::string &getColumnName(size_t index) noexcept(false);

    Json::Value toJson() const;
    Json::Value toMasqueradedJson(const std::vector<std::string> &pMasqueradingVector) const;
    /// Relationship interfaces
  private:
    friend drogon::orm::Mapper<Users>;
#ifdef __cpp_impl_coroutine
    friend drogon::orm::CoroMapper<Users>;
#endif
    static const std::vector<std::string> &insertColumns() noexcept;
    void outputArgs(drogon::orm::internal::SqlBinder &binder) const;
    const std::vector<std::string> updateColumns() const;
    void updateArgs(drogon::orm::internal::SqlBinder &binder) const;
    ///For mysql or sqlite3
    void updateId(const uint64_t id);
    std::shared_ptr<int64_t> userid_;
    std::shared_ptr<std::vector<char>> email_;
    std::shared_ptr<std::vector<char>> emailnonce_;
    std::shared_ptr<std::vector<char>> emailsearchable_;
    std::shared_ptr<::trantor::Date> lastlogin_;
    std::shared_ptr<std::string> username_;
    std::shared_ptr<std::vector<char>> passwordhash_;
    std::shared_ptr<std::vector<char>> passwordsalt_;
    std::shared_ptr<std::string> gender_;
    std::shared_ptr<std::vector<char>> profilepicture_;
    std::shared_ptr<std::string> profilepictureurl_;
    std::shared_ptr<int32_t> birthyear_;
    std::shared_ptr<std::vector<char>> permanentlocation_;
    std::shared_ptr<std::vector<char>> permanentlocationnonce_;
    std::shared_ptr<std::string> displayname_;
    std::shared_ptr<int32_t> incorrectPasswordAttempts_;
    std::shared_ptr<::trantor::Date> incorrectPasswordAttemptDate_;
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
    bool dirtyFlag_[17]={ false };
  public:
    static const std::string &sqlForFindingByPrimaryKey()
    {
        static const std::string sql="select * from " + tableName + " where userid = $1";
        return sql;
    }

    static const std::string &sqlForDeletingByPrimaryKey()
    {
        static const std::string sql="delete from " + tableName + " where userid = $1";
        return sql;
    }
    std::string sqlForInserting(bool &needSelection) const
    {
        std::string sql="insert into " + tableName + " (";
        size_t parametersCount = 0;
        needSelection = false;
            sql += "userid,";
            ++parametersCount;
        if(dirtyFlag_[1])
        {
            sql += "email,";
            ++parametersCount;
        }
        if(dirtyFlag_[2])
        {
            sql += "emailnonce,";
            ++parametersCount;
        }
        if(dirtyFlag_[3])
        {
            sql += "emailsearchable,";
            ++parametersCount;
        }
        if(dirtyFlag_[4])
        {
            sql += "lastlogin,";
            ++parametersCount;
        }
        if(dirtyFlag_[5])
        {
            sql += "username,";
            ++parametersCount;
        }
        if(dirtyFlag_[6])
        {
            sql += "passwordhash,";
            ++parametersCount;
        }
        if(dirtyFlag_[7])
        {
            sql += "passwordsalt,";
            ++parametersCount;
        }
        if(dirtyFlag_[8])
        {
            sql += "gender,";
            ++parametersCount;
        }
        if(dirtyFlag_[9])
        {
            sql += "profilepicture,";
            ++parametersCount;
        }
        if(dirtyFlag_[10])
        {
            sql += "profilepictureurl,";
            ++parametersCount;
        }
        if(dirtyFlag_[11])
        {
            sql += "birthyear,";
            ++parametersCount;
        }
        if(dirtyFlag_[12])
        {
            sql += "permanentlocation,";
            ++parametersCount;
        }
        if(dirtyFlag_[13])
        {
            sql += "permanentlocationnonce,";
            ++parametersCount;
        }
        if(dirtyFlag_[14])
        {
            sql += "displayname,";
            ++parametersCount;
        }
        if(dirtyFlag_[15])
        {
            sql += "incorrect_password_attempts,";
            ++parametersCount;
        }
        if(dirtyFlag_[16])
        {
            sql += "incorrect_password_attempt_date,";
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
        if(dirtyFlag_[13])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[14])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[15])
        {
            n = sprintf(placeholderStr,"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[16])
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
