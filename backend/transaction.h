#pragma once 
#include <drogon/orm/DbClient.h>
#include <drogon/drogon.h>
#include <exception>
#include <memory>

#define transaction auto trans = co_await drogon::app().getFastDbClient()->newTransactionCoro();  try 
#define commit catch (...) {trans->rollback(); std::rethrow_exception(std::current_exception());}