#include "DNNConfigIO.h"
namespace sgx {
namespace trusted {
namespace darknet {

DNNConfigIO::DNNConfigIO(const std::string &config_file_path,
                         const sgt::CryptoEngine<uint8_t> &crypto_engine)
    : IO(crypto_engine, IOCipher(0), IOPlain(0)),
      configFilePath_(config_file_path) {}

bool DNNConfigIO::receiveFromUntrusted(
    const std::function<decltype(ocall_load_net_config)> &read_handler) {
  IOCipher cipher(100000);
  int len = 0;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  // TODO: replace unsafe conversions down below!
  ret = read_handler((const unsigned char *)configFilePath_.c_str(),
                     configFilePath_.size(), (char *)&cipher[0], len);
  if (ret != SGX_SUCCESS)
    return false;

  cipher.resize(len);
  emptyCipherBuffer();
  appendToCipher(cipher);
  return true;
}
}
}
}
