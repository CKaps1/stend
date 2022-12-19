#include "EncryptionContext.h"
#include "city.h"
#include "co.h"
#include <sodium.h>
#include <fstream>
#include <cmath>

using namespace stend;
using namespace std;

constexpr size_t maclen = crypto_secretbox_MACBYTES;
constexpr size_t keylen = crypto_secretbox_KEYBYTES;
constexpr size_t noncelen = crypto_secretbox_NONCEBYTES;
constexpr size_t saltlen = crypto_pwhash_argon2id_SALTBYTES;
constexpr size_t master_keylen = crypto_kdf_blake2b_KEYBYTES;
#define encrypt crypto_secretbox_easy
#define decrypt crypto_secretbox_open_easy
#define derive crypto_kdf_blake2b_derive_from_key

typedef struct
{
    int64_t a, b, c;
} hash192_t;

inline void hash192(char* data, size_t sz, hash192_t& hsh)
{
    auto ac = CityHash128(data, sz);
    hsh.a = Uint128High64(ac);
    hsh.c = Uint128Low64(ac);
    hsh.b = Hash128to64(ac);
}

inline void hash192(binary bin, hash192_t& hsh)
{
    hash192(bin.data(), bin.size(), hsh);
}

inline void hash192(string str, hash192_t& hsh)
{
    hash192((char*)str.c_str(), str.length(), hsh);
}


void stend::EncryptionContext::initAndStart(const Json::Value& config)
{
    co(sodium_init());

    string filepath;
    if (config.isMember("key_file")) filepath = config["key_file"].asString();
    else filepath = "/etc/stend/keys";

    ifstream ifs(filepath, ios::binary);
    while (!ifs.eof())
    {
        int32_t id = 0;
        EncryptionKeyPtr key = make_shared<EncryptionKey>(master_keylen);
        ifs.read(reinterpret_cast<char*>(&id), sizeof id);
        ifs.read(key->operator char *(), key->Size());
        keys.insert(make_pair(id, key));
    }
}

void stend::EncryptionContext::shutdown()
{
}

binary stend::EncryptionContext::EncryptSearchable(int64_t ctx, std::string msg, int id)
{
    hash192_t hash;
    hash192(msg, hash);
    binary nonce(reinterpret_cast<char*>(&hash), sizeof(hash));
    return Encrypt(CityHash64(msg.c_str(), msg.length()), ctx, msg, nonce, id);
}

binary stend::EncryptionContext::EncryptSearchable(int64_t ctx, binary msg, int id)
{
    hash192_t hash;
    hash192(msg, hash);
    binary nonce(reinterpret_cast<char*>(&hash), sizeof(hash));
    return Encrypt(CityHash64(msg.data(), msg.size()), ctx, msg, nonce, id);
}

binary stend::EncryptionContext::Encrypt(int64_t index, int64_t ctx, std::string msg, binary& nonce, int id)
{
    EncryptionKey key(keylen);
    derive(key, key.Size(), index, reinterpret_cast<char*>(&ctx), keys[id]->operator uint8_t * ());
    binary cypher(msg.length() + maclen);
    co(encrypt(
        reinterpret_cast<unsigned char*>(cypher.data()),
        (const unsigned char*)msg.c_str(),
        msg.length(),
        (const unsigned char*)nonce.data(),
        key
    ));
    return cypher;
}

binary stend::EncryptionContext::Encrypt(int64_t index, int64_t ctx, binary msg, binary& nonce, int id)
{
    EncryptionKey key(keylen);
    derive(key, key.Size(), index, reinterpret_cast<char*>(&ctx), keys[id]->operator uint8_t * ());
    binary cypher(msg.size() + maclen);

    co(encrypt(
        reinterpret_cast<unsigned char*>(cypher.data()),
        (const unsigned char*)msg.data(),
        msg.size(),
        (const unsigned char*)nonce.data(),
        key
    ));
    return cypher;
}

binary stend::EncryptionContext::DecryptBin(int64_t index, int64_t ctx, binary crypto, binary& nonce, int id)
{
    EncryptionKey key(keylen);
    derive(key, key.Size(), index, reinterpret_cast<char*>(&ctx), keys[id]->operator uint8_t * ());
    binary msg(crypto.size() - maclen);
    co(decrypt(reinterpret_cast<unsigned char*>(msg.data()),
        (unsigned char*)crypto.data(),
        crypto.size(),
        (const unsigned char*)nonce.data(),
        key));
    return msg;
}

std::string stend::EncryptionContext::DecryptStr(int64_t index, int64_t ctx, binary crypto, binary& nonce, int id)
{
    EncryptionKey key(keylen);
    derive(key, key.Size(), index, reinterpret_cast<char*>(&ctx), keys[id]->operator uint8_t * ());
    size_t size = crypto.size() - maclen;
    unique_ptr<char> msg(new char[size]);
    co(decrypt(reinterpret_cast<unsigned char*>(msg.get()),
        (const unsigned char*)crypto.data(),
        crypto.size(),
        (const unsigned char*)nonce.data(),
        key));

    return string(msg.get(), size);
}

binary stend::EncryptionContext::Hash(binary msg, size_t hashsize, binary salt)
{
    binary hash(hashsize);
    co(crypto_pwhash_argon2id((unsigned char*)hash.data(), hash.size(), msg.data(), msg.size(), (unsigned char*)salt.data(),
        crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE, crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_ARGON2ID13));
    return hash;
}

binary stend::EncryptionContext::Hash(std::string msg, size_t hashsize, binary salt)
{
    binary hash(hashsize);
    co(crypto_pwhash_argon2id((unsigned char*)hash.data(), hash.size(), msg.c_str(), msg.length(), (unsigned char*)salt.data(),
        crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE, crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_ARGON2ID13));
    return hash;
}

binary stend::EncryptionContext::RandomNonce()
{
    binary nonce(noncelen);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

binary stend::EncryptionContext::RandomSalt()
{
    binary salt(saltlen);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

binary stend::EncryptionContext::Random(size_t sz)
{
    binary bin(sz);
    randombytes_buf(bin.data(), bin.size());
    return bin;
}

int64_t stend::EncryptionContext::Random64()
{
    int64_t random;
    randombytes_buf(&random, sizeof random);
    return abs(random);
}

