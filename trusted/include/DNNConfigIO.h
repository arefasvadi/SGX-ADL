#pragma once

#include "IO.h"
#include "enclave-app.h"
#include "enclave_t.h"
#include <functional>
#include <string>

extern void printf(const char *fmt, ...);
namespace sgx {
namespace trusted {
namespace darknet {
namespace std = ::std;
namespace sgt = ::sgx::trusted;
class DNNConfigIO
    : public sgt::IO<std::function<decltype(ocall_load_net_config)>,
                     std::function<void(void)>, uint8_t, uint8_t> {
public:
  explicit DNNConfigIO(const std::string &config_file_path,
                       const sgt::CryptoEngine<uint8_t> &crypto_engine);

  // TODO try to have the type name in a variable of parent!
  bool
  sendToUntrusted(const std::function<void(void)> &write_handler) override {
    return false;
  };

  bool receiveFromUntrusted(const std::function<decltype(ocall_load_net_config)>
                                &read_handler) override;

  // ~DNNConfigIO() override { printf("DNNConfigIO destructor is called!\n"); };
  inline const std::string getNetConfig() const { return netConfig_; }

private:
  const std::string configFilePath_;
  std::string netConfig_;
};
}
}
}
