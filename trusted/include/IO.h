#pragma once

#include <algorithm>
#include <array>
#include <functional>
#include <stdexcept>
#include <utility>
#include <vector>
#include "CryptoEngine.hpp"

namespace sgx {
namespace trusted {
/* @brief this class is responsible to handle IO communication between SGX
 * enclave and untrusted domain.
 * @tparam C type of a single unit received/will be sent from/to untrusted and
 * it is usually
 * encrypted.
 * @tparam P type of single unit befor/after C is encrypted/decrypted inside SGX
 * enclave.
 * @tparam FR type of function handler that will be called to handle read from
 * untrusted to enclave. std::function<> is preferred.
 * @tparam FS type of function handler that will be called to handle write to
 * untrsuted from enclave. std::function<> is preferred.
 */
namespace std = ::std;
// namespace sgt = ::sgx::trusted;
template <typename FR, typename FS, typename C = uint8_t, typename P = uint8_t>
class IO {
public:
  using IOCipher = std::vector<C>;
  using IOPlain = std::vector<P>;

  explicit IO(const CryptoEngine<uint8_t> &cryptoEngine,
              const IOCipher &cipherBuff, const IOPlain &plainBuff);
  IO(const IO &) = delete;
  IO(IO &&) = delete;

  IO &operator=(const IO &) = delete;
  IO &operator=(IO &&) = delete;

  virtual bool appendToCipher(const IOCipher &bytes);
  virtual bool appendToPlain(const IOPlain &bytes);
  virtual void emptyCipherBuffer();
  virtual void emptyPlainBuffer();
  virtual bool sendToUntrusted(const FS &write_handler) = 0;
  virtual bool receiveFromUntrusted(const FR &read_handler) = 0;
  virtual ~IO(){};

protected:
  IOCipher cipherBuffer_;
  IOPlain plainBuffer_;
  const CryptoEngine<uint8_t> &cryptoEngine_;
};
template <typename FR, typename FS, typename C, typename P>
IO<FR, FS, C, P>::IO(const CryptoEngine<uint8_t> &crypto_engine,
                     const IOCipher &cipher_buff, const IOPlain &plain_buff)
    : cryptoEngine_(crypto_engine), cipherBuffer_(cipher_buff),
      plainBuffer_(plain_buff){};

template <typename FR, typename FS, typename C, typename P>
void IO<FR, FS, C, P>::emptyCipherBuffer() {
  cipherBuffer_.clear();
}

template <typename FR, typename FS, typename C, typename P>
void IO<FR, FS, C, P>::emptyPlainBuffer() {
  plainBuffer_.clear();
}

template <typename FR, typename FS, typename C, typename P>
bool IO<FR, FS, C, P>::appendToCipher(const IOCipher &bytes) {
  cipherBuffer_.insert(cipherBuffer_.end(), bytes.begin(), bytes.end());
  return true;
}

template <typename FR, typename FS, typename C, typename P>
bool IO<FR, FS, C, P>::appendToPlain(const IOPlain &bytes) {
  plainBuffer_.insert(plainBuffer_.end(), bytes.begin(), bytes.end());
  return true;
}
}
}
