#include "DNNConfigIO.h"

namespace sgx {
namespace trusted {
namespace darknet {

DNNConfigIO::DNNConfigIO(const std::string &config_file_path,
                         const sgt::CryptoEngine<uint8_t> &crypto_engine)
    : IO(crypto_engine, IOCipher(0), IOPlain(0)),
      configFilePath_(config_file_path), netConfig_() {}

bool DNNConfigIO::receiveFromUntrusted(
    const std::function<decltype(ocall_load_net_config)> &read_handler) {
  // TODO: probably this size should be set to constant defined in a constexpr!
  int len = 10000;
  unsigned int real_len = 0;
  IOCipher cipher(len);
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  CryptoEngine<uint8_t>::IV config_iv;
  CryptoEngine<uint8_t>::MAC config_mac;

  // TODO: replace unsafe conversions down below!
  my_printf(
      "%s:%d@%s =>  the path from receive untrusted is %s with size %zu\n",
      __FILE__, __LINE__, __func__, configFilePath_.c_str(),
      configFilePath_.size());
  ret = read_handler((const unsigned char *)configFilePath_.c_str(),
                     configFilePath_.size(), (char *)&cipher[0], len, &real_len,
                     config_iv.data(), config_mac.data());
  if (ret != SGX_SUCCESS) {
    my_printf("%s:%d@%s =>  return status was not successful!\n", __FILE__,
              __LINE__, __func__);
    return false;
  }
  cipher.resize(real_len);
  // emptyCipherBuffer();
  // appendToCipher(cipher);

  const auto decrypted =
      cryptoEngine_.decrypt(std::make_tuple<>(cipher, config_iv, config_mac));

  emptyPlainBuffer();
  appendToPlain(decrypted);

  netConfig_ = std::string(decrypted.begin(),decrypted.end());
  my_printf("%s:%d@%s =>  Network config size was %d bytes!\n", __FILE__,
            __LINE__, __func__, real_len);
  // my_printf("%s:%d@%s => Network file content is:\n%s", __FILE__, __LINE__,
  //        __func__, &decrypted[0]);

  return true;
}
}
}
}
