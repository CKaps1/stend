#include "binary.h"
#include "co.h"
#include <sodium.h>
#include <memory>
#include <cstring>

using namespace stend;
using namespace std;

std::string stend::bin_to_hex(binary bin)
{
	size_t hexsz = (1 + bin.size()) * 2;
	std::unique_ptr<char> hex(new char[hexsz]);
	(sodium_bin2hex(hex.get(), hexsz, (const unsigned char*)bin.data(), bin.size()));
	return std::string(hex.get());
}

binary stend::hex_to_bin(std::string hex)
{
	size_t bl;
	binary bin(hex.length() / 2);
	co(sodium_hex2bin((unsigned char*)bin.data(), bin.size(), hex.c_str(), hex.length(), "", &bl, 0));
	dynamic_assert(bl == bin.size());
	return bin;
}

std::string stend::bin_to_b64(binary bin)
{
	size_t b64sz = (1 + bin.size()) * 2;
	std::unique_ptr<char> b64(new char[b64sz]);
	(sodium_bin2base64(b64.get(), b64sz, (const unsigned char*)bin.data(), bin.size(), 7));
	return std::string(b64.get());
}

binary stend::b64_to_bin(std::string b64)
{
	binary bin(b64.length());
	size_t bl;
	co(sodium_base642bin((unsigned char*)bin.data(), bin.size(), b64.c_str(), b64.length(), "", &bl, 0, 7));
	bin.resize(bl);
	return bin;
}

void randomContext(char ctx[8])
{
	char bin[6];
	randombytes_buf(bin, sizeof(bin));
	sodium_bin2base64(ctx, 8, (const unsigned char*)bin, 6, 7);
}

binary::binary(size_t sz) : vector(sz)
{
}

binary::binary(vector<char> value) : vector<char>(value)
{
}

binary::binary(char* data_, size_t sz) : vector<char>(sz)
{
	std::memcpy(data(), data_, sz);
}

stend::binary::binary(Json::Value value)
{
	this->operator=(b64_to_bin(value.asString()));
}

stend::binary::binary(std::string s)
{
	this->operator=(b64_to_bin(s));
}

binary::binary() : vector()
{
}

bool binary::operator==(binary& other)
{
	if (other.size() != size()) return false;
	return !std::memcmp(data(), other.data(), size());
}

binary binary::operator=(const vector<char>& other)
{
	vector<char>::operator=(other);
	return *this;
}

binary stend::binary::operator=(const Json::Value& other)
{
	this->operator=(b64_to_bin(other.asString()));
	return *this;
}

binary stend::binary::operator=(const std::string& other)
{
	this->operator=(b64_to_bin(other));
	return *this;
}

stend::binary::operator Json::Value()
{
	return Json::Value(bin_to_b64(*this));
}

binary::operator std::string()
{
	return bin_to_b64(*this);
}