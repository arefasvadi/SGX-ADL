// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_AES128GCM_H_
#define FLATBUFFERS_GENERATED_AES128GCM_H_

#include "flatbuffers/flatbuffers.h"

struct AESGCM128Enc;
struct AESGCM128EncT;

inline const flatbuffers::TypeTable *AESGCM128EncTypeTable();

struct AESGCM128EncT : public flatbuffers::NativeTable {
  typedef AESGCM128Enc TableType;
  std::vector<uint8_t> enc_content;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> mac;
  std::vector<uint8_t> aad;
  AESGCM128EncT() {
  }
};

struct AESGCM128Enc FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef AESGCM128EncT NativeTableType;
  static const flatbuffers::TypeTable *MiniReflectTypeTable() {
    return AESGCM128EncTypeTable();
  }
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ENC_CONTENT = 4,
    VT_IV = 6,
    VT_MAC = 8,
    VT_AAD = 10
  };
  const flatbuffers::Vector<uint8_t> *enc_content() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_ENC_CONTENT);
  }
  flatbuffers::Vector<uint8_t> *mutable_enc_content() {
    return GetPointer<flatbuffers::Vector<uint8_t> *>(VT_ENC_CONTENT);
  }
  const flatbuffers::Vector<uint8_t> *iv() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_IV);
  }
  flatbuffers::Vector<uint8_t> *mutable_iv() {
    return GetPointer<flatbuffers::Vector<uint8_t> *>(VT_IV);
  }
  const flatbuffers::Vector<uint8_t> *mac() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_MAC);
  }
  flatbuffers::Vector<uint8_t> *mutable_mac() {
    return GetPointer<flatbuffers::Vector<uint8_t> *>(VT_MAC);
  }
  const flatbuffers::Vector<uint8_t> *aad() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_AAD);
  }
  flatbuffers::Vector<uint8_t> *mutable_aad() {
    return GetPointer<flatbuffers::Vector<uint8_t> *>(VT_AAD);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ENC_CONTENT) &&
           verifier.VerifyVector(enc_content()) &&
           VerifyOffsetRequired(verifier, VT_IV) &&
           verifier.VerifyVector(iv()) &&
           VerifyOffsetRequired(verifier, VT_MAC) &&
           verifier.VerifyVector(mac()) &&
           VerifyOffset(verifier, VT_AAD) &&
           verifier.VerifyVector(aad()) &&
           verifier.EndTable();
  }
  AESGCM128EncT *UnPack(const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  void UnPackTo(AESGCM128EncT *_o, const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  static flatbuffers::Offset<AESGCM128Enc> Pack(flatbuffers::FlatBufferBuilder &_fbb, const AESGCM128EncT* _o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);
};

struct AESGCM128EncBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_enc_content(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> enc_content) {
    fbb_.AddOffset(AESGCM128Enc::VT_ENC_CONTENT, enc_content);
  }
  void add_iv(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> iv) {
    fbb_.AddOffset(AESGCM128Enc::VT_IV, iv);
  }
  void add_mac(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> mac) {
    fbb_.AddOffset(AESGCM128Enc::VT_MAC, mac);
  }
  void add_aad(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> aad) {
    fbb_.AddOffset(AESGCM128Enc::VT_AAD, aad);
  }
  explicit AESGCM128EncBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  AESGCM128EncBuilder &operator=(const AESGCM128EncBuilder &);
  flatbuffers::Offset<AESGCM128Enc> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<AESGCM128Enc>(end);
    fbb_.Required(o, AESGCM128Enc::VT_ENC_CONTENT);
    fbb_.Required(o, AESGCM128Enc::VT_IV);
    fbb_.Required(o, AESGCM128Enc::VT_MAC);
    return o;
  }
};

inline flatbuffers::Offset<AESGCM128Enc> CreateAESGCM128Enc(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> enc_content = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> iv = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> mac = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> aad = 0) {
  AESGCM128EncBuilder builder_(_fbb);
  builder_.add_aad(aad);
  builder_.add_mac(mac);
  builder_.add_iv(iv);
  builder_.add_enc_content(enc_content);
  return builder_.Finish();
}

inline flatbuffers::Offset<AESGCM128Enc> CreateAESGCM128EncDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *enc_content = nullptr,
    const std::vector<uint8_t> *iv = nullptr,
    const std::vector<uint8_t> *mac = nullptr,
    const std::vector<uint8_t> *aad = nullptr) {
  auto enc_content__ = enc_content ? _fbb.CreateVector<uint8_t>(*enc_content) : 0;
  auto iv__ = iv ? _fbb.CreateVector<uint8_t>(*iv) : 0;
  auto mac__ = mac ? _fbb.CreateVector<uint8_t>(*mac) : 0;
  auto aad__ = aad ? _fbb.CreateVector<uint8_t>(*aad) : 0;
  return CreateAESGCM128Enc(
      _fbb,
      enc_content__,
      iv__,
      mac__,
      aad__);
}

flatbuffers::Offset<AESGCM128Enc> CreateAESGCM128Enc(flatbuffers::FlatBufferBuilder &_fbb, const AESGCM128EncT *_o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);

inline AESGCM128EncT *AESGCM128Enc::UnPack(const flatbuffers::resolver_function_t *_resolver) const {
  auto _o = new AESGCM128EncT();
  UnPackTo(_o, _resolver);
  return _o;
}

inline void AESGCM128Enc::UnPackTo(AESGCM128EncT *_o, const flatbuffers::resolver_function_t *_resolver) const {
  (void)_o;
  (void)_resolver;
  { auto _e = enc_content(); if (_e) { _o->enc_content.resize(_e->size()); for (flatbuffers::uoffset_t _i = 0; _i < _e->size(); _i++) { _o->enc_content[_i] = _e->Get(_i); } } }
  { auto _e = iv(); if (_e) { _o->iv.resize(_e->size()); for (flatbuffers::uoffset_t _i = 0; _i < _e->size(); _i++) { _o->iv[_i] = _e->Get(_i); } } }
  { auto _e = mac(); if (_e) { _o->mac.resize(_e->size()); for (flatbuffers::uoffset_t _i = 0; _i < _e->size(); _i++) { _o->mac[_i] = _e->Get(_i); } } }
  { auto _e = aad(); if (_e) { _o->aad.resize(_e->size()); for (flatbuffers::uoffset_t _i = 0; _i < _e->size(); _i++) { _o->aad[_i] = _e->Get(_i); } } }
}

inline flatbuffers::Offset<AESGCM128Enc> AESGCM128Enc::Pack(flatbuffers::FlatBufferBuilder &_fbb, const AESGCM128EncT* _o, const flatbuffers::rehasher_function_t *_rehasher) {
  return CreateAESGCM128Enc(_fbb, _o, _rehasher);
}

inline flatbuffers::Offset<AESGCM128Enc> CreateAESGCM128Enc(flatbuffers::FlatBufferBuilder &_fbb, const AESGCM128EncT *_o, const flatbuffers::rehasher_function_t *_rehasher) {
  (void)_rehasher;
  (void)_o;
  struct _VectorArgs { flatbuffers::FlatBufferBuilder *__fbb; const AESGCM128EncT* __o; const flatbuffers::rehasher_function_t *__rehasher; } _va = { &_fbb, _o, _rehasher}; (void)_va;
  auto _enc_content = _fbb.CreateVector(_o->enc_content);
  auto _iv = _fbb.CreateVector(_o->iv);
  auto _mac = _fbb.CreateVector(_o->mac);
  auto _aad = _o->aad.size() ? _fbb.CreateVector(_o->aad) : 0;
  return CreateAESGCM128Enc(
      _fbb,
      _enc_content,
      _iv,
      _mac,
      _aad);
}

inline const flatbuffers::TypeTable *AESGCM128EncTypeTable() {
  static const flatbuffers::TypeCode type_codes[] = {
    { flatbuffers::ET_UCHAR, 1, -1 },
    { flatbuffers::ET_UCHAR, 1, -1 },
    { flatbuffers::ET_UCHAR, 1, -1 },
    { flatbuffers::ET_UCHAR, 1, -1 }
  };
  static const flatbuffers::TypeTable tt = {
    flatbuffers::ST_TABLE, 4, type_codes, nullptr, nullptr, nullptr
  };
  return &tt;
}

inline const AESGCM128Enc *GetAESGCM128Enc(const void *buf) {
  return flatbuffers::GetRoot<AESGCM128Enc>(buf);
}

inline const AESGCM128Enc *GetSizePrefixedAESGCM128Enc(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<AESGCM128Enc>(buf);
}

inline AESGCM128Enc *GetMutableAESGCM128Enc(void *buf) {
  return flatbuffers::GetMutableRoot<AESGCM128Enc>(buf);
}

inline bool VerifyAESGCM128EncBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<AESGCM128Enc>(nullptr);
}

inline bool VerifySizePrefixedAESGCM128EncBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<AESGCM128Enc>(nullptr);
}

inline void FinishAESGCM128EncBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<AESGCM128Enc> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedAESGCM128EncBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<AESGCM128Enc> root) {
  fbb.FinishSizePrefixed(root);
}

inline std::unique_ptr<AESGCM128EncT> UnPackAESGCM128Enc(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<AESGCM128EncT>(GetAESGCM128Enc(buf)->UnPack(res));
}

inline std::unique_ptr<AESGCM128EncT> UnPackSizePrefixedAESGCM128Enc(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<AESGCM128EncT>(GetSizePrefixedAESGCM128Enc(buf)->UnPack(res));
}

#endif  // FLATBUFFERS_GENERATED_AES128GCM_H_
