#pragma once
#include <vector>
#include <string>
#include <json/json.h>

namespace stend
{
	class binary : public std::vector<char>
	{
	public:
		binary(size_t sz);
		binary(vector<char> value);
		binary(char* data, size_t sz);
		binary(Json::Value);
		binary(std::string);
		binary();
		bool operator==(binary& other);
		binary operator=(const std::vector<char>& other);
		binary operator=(const Json::Value& other);
		binary operator=(const std::string& other);
		operator Json::Value();
		operator std::string();
	};
	std::string bin_to_hex(binary bin);
	binary hex_to_bin(std::string hex);
	std::string bin_to_b64(binary bin);
	binary b64_to_bin(std::string b64);


};