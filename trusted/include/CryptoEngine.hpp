#pragma once

#include "common.h"
#include "enclave-app.h"
#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include <array>
#include <cstdio>
#include <stdexcept>
#include <tuple>
#include <utility>
#include <vector>

// extern void my_printf(const char *fmt, ...);

namespace sgx {
namespace trusted {
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

  // auto key_data = key_.data();
  sgx_status_t success = SGX_ERROR_UNEXPECTED;
  success = sgx_rijndael128GCM_encrypt(
      (uint8_t const(*)[16]) & key_, (const uint8_t *)plain_text.data(),
      plain_text.size() * sizeof(T), (uint8_t *)cipher.data(), iv.data(),
      iv.size(), nullptr, 0, (uint8_t(*)[16]) & mac);

  if (success != SGX_SUCCESS) {
    my_printf("Eecryption failed! Error code is %#010x and in decimal %d \n", success,success);
    abort();
  }
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
  // IOBuffer cipher;
  // IV iv;
  // MAC mac;

  // std::tie(cipher, iv, mac) = cipher_text;
  auto& cipher = std::get<0>(cipher_text);
  auto& iv = std::get<1>(cipher_text);
  auto& mac = std::get<2>(cipher_text);

  // static_assert(iv.size() == 12, "IV size is zero!");
  // static_assert(mac.size() == 16, "MAC size is zero!");
  plain.resize(cipher.size());
  // auto key_data = key_.data();
  sgx_status_t success = SGX_ERROR_UNEXPECTED;
  success = sgx_rijndael128GCM_decrypt(
                                       (uint8_t const(*)[16])  key_.data(), (const uint8_t *)cipher.data(),
      cipher.size(), (uint8_t *)plain.data(), iv.data(), iv.size(), nullptr, 0,
                                       (uint8_t const(*)[16]) mac.data());
  if (success != SGX_SUCCESS) {
    my_printf("Decryption failed! Error code is %#010x and in decimal %d \n", success,success);
    abort();
  }
  // my_printf("After decryption\n");
  return plain;
}
}
}
