#pragma once

#include "common.h"
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace sgx {
namespace untrusted {
// TODO: maybe in future this class should be written with templates for wider
// support.
// TODO: make sure the class is non-copiable and non-movable
// TODO: IV should is not secure, do not use for production code
namespace std = ::std;
template <typename T = uint8_t> class CryptoEngine {
public:
  using Key = std::array<uint8_t, AES_GCM_KEY_SIZE>;
  using IV = std::array<uint8_t, AES_GCM_IV_SIZE>;
  using MAC = std::array<uint8_t, AES_GCM_TAG_SIZE>;
  using IOBuffer = std::vector<T>;
  // using IOBuffer = std::vector<uint8_t>;

  explicit CryptoEngine(const Key &key);
  std::tuple<IOBuffer, IV, MAC> encrypt(const IOBuffer &plain_text);
  IOBuffer decrypt(const std::tuple<IOBuffer, IV, MAC> &cipher_text) const;

  // making class non-copyable
  explicit CryptoEngine(const CryptoEngine &) = delete;
  CryptoEngine &operator=(const CryptoEngine &) = delete;

  // making class non-movable
  explicit CryptoEngine(CryptoEngine &&) = delete;
  CryptoEngine &operator=(CryptoEngine &&) = delete;

private:
  const Key key_;
  // for IV look into
  // https://crypto.stackexchange.com/questions/31196/randomness-and-increment-of-nonce-in-gcm
  // IV iv_;
  uint64_t counter_;
};

template <typename T>
CryptoEngine<T>::CryptoEngine(const Key &key)
    : key_(key), counter_(0)
// iv_({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
{}

// unsafe operation of increment on iv_ is done.
template <typename T>
std::tuple<typename CryptoEngine<T>::IOBuffer, typename CryptoEngine<T>::IV,
           typename CryptoEngine<T>::MAC>
CryptoEngine<T>::encrypt(const CryptoEngine<T>::IOBuffer &plain_text) {

  IOBuffer cipher(plain_text.size(), 0);
  IV iv({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  std::memcpy(iv.data(), (uint8_t *)&counter_, iv.size());
  MAC mac;
  // static_assert(iv_.size() == 12, "IV size is zero!");
  // static_assert(mac.size() == 16, "MAC size is zero!");

  int actual_size = 0, final_size = 0;

  EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
  EVP_EncryptInit(e_ctx, EVP_aes_128_gcm(), (const unsigned char *)key_.data(),
                  (const unsigned char *)iv.data());
  EVP_EncryptUpdate(e_ctx, (unsigned char *)cipher.data(), &actual_size,
                    (const unsigned char *)plain_text.data(),
                    plain_text.size());
  EVP_EncryptFinal(e_ctx, (unsigned char *)&cipher[actual_size], &final_size);
  final_size += actual_size;
  EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, mac.size(),
                      (unsigned char *)mac.data());
  EVP_CIPHER_CTX_free(e_ctx);
  ++counter_;
  // TODO When IV fixed you can use std::move
  return std::make_tuple(cipher, iv, mac);
}

template <typename T>
typename CryptoEngine<T>::IOBuffer CryptoEngine<T>::decrypt(
    const std::tuple<typename CryptoEngine<T>::IOBuffer,
                     typename CryptoEngine<T>::IV,
                     typename CryptoEngine<T>::MAC> &cipher_text) const {
  IOBuffer plain;
  IOBuffer cipher;
  IV iv;
  MAC mac;

  int actual_size = 0, final_size = 0;
  int ret_val = 0;
  EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();

  std::tie(cipher, iv, mac) = cipher_text;
  // static_assert(iv.size() == 12, "IV size is zero!");
  // static_assert(mac.size() == 16, "MAC size is zero!");
  plain.resize(cipher.size());

  //	EVP_CIPHER_CTX *d_ctx;
  ret_val = EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
  EVP_DecryptInit(d_ctx, EVP_aes_128_gcm(), (const unsigned char *)key_.data(),
                  (const unsigned char *)iv.data());
  EVP_DecryptUpdate(d_ctx, (unsigned char *)plain.data(), &actual_size,
                    (const unsigned char *)cipher.data(), cipher.size());

  //	final_size = actual_size;
  EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, mac.size(),
                      (unsigned char *)mac.data());
  EVP_DecryptFinal(d_ctx, (unsigned char *)&plain[actual_size], &final_size);
  final_size += actual_size;
  EVP_CIPHER_CTX_free(d_ctx);

  return plain;
}
}
}
