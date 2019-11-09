// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_PLAINLABELMETA_H_
#define FLATBUFFERS_GENERATED_PLAINLABELMETA_H_

#include "flatbuffers/flatbuffers.h"

struct PlainLabelMeta;
struct PlainLabelMetaT;

inline const flatbuffers::TypeTable *PlainLabelMetaTypeTable();

struct PlainLabelMetaT : public flatbuffers::NativeTable {
  typedef PlainLabelMeta TableType;
  int32_t numClasses;
  PlainLabelMetaT()
      : numClasses(0) {
  }
};

struct PlainLabelMeta FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef PlainLabelMetaT NativeTableType;
  static const flatbuffers::TypeTable *MiniReflectTypeTable() {
    return PlainLabelMetaTypeTable();
  }
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NUMCLASSES = 4
  };
  int32_t numClasses() const {
    return GetField<int32_t>(VT_NUMCLASSES, 0);
  }
  bool mutate_numClasses(int32_t _numClasses) {
    return SetField<int32_t>(VT_NUMCLASSES, _numClasses, 0);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<int32_t>(verifier, VT_NUMCLASSES) &&
           verifier.EndTable();
  }
  PlainLabelMetaT *UnPack(const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  void UnPackTo(PlainLabelMetaT *_o, const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  static flatbuffers::Offset<PlainLabelMeta> Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainLabelMetaT* _o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);
};

struct PlainLabelMetaBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_numClasses(int32_t numClasses) {
    fbb_.AddElement<int32_t>(PlainLabelMeta::VT_NUMCLASSES, numClasses, 0);
  }
  explicit PlainLabelMetaBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  PlainLabelMetaBuilder &operator=(const PlainLabelMetaBuilder &);
  flatbuffers::Offset<PlainLabelMeta> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<PlainLabelMeta>(end);
    return o;
  }
};

inline flatbuffers::Offset<PlainLabelMeta> CreatePlainLabelMeta(
    flatbuffers::FlatBufferBuilder &_fbb,
    int32_t numClasses = 0) {
  PlainLabelMetaBuilder builder_(_fbb);
  builder_.add_numClasses(numClasses);
  return builder_.Finish();
}

flatbuffers::Offset<PlainLabelMeta> CreatePlainLabelMeta(flatbuffers::FlatBufferBuilder &_fbb, const PlainLabelMetaT *_o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);

inline PlainLabelMetaT *PlainLabelMeta::UnPack(const flatbuffers::resolver_function_t *_resolver) const {
  auto _o = new PlainLabelMetaT();
  UnPackTo(_o, _resolver);
  return _o;
}

inline void PlainLabelMeta::UnPackTo(PlainLabelMetaT *_o, const flatbuffers::resolver_function_t *_resolver) const {
  (void)_o;
  (void)_resolver;
  { auto _e = numClasses(); _o->numClasses = _e; }
}

inline flatbuffers::Offset<PlainLabelMeta> PlainLabelMeta::Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainLabelMetaT* _o, const flatbuffers::rehasher_function_t *_rehasher) {
  return CreatePlainLabelMeta(_fbb, _o, _rehasher);
}

inline flatbuffers::Offset<PlainLabelMeta> CreatePlainLabelMeta(flatbuffers::FlatBufferBuilder &_fbb, const PlainLabelMetaT *_o, const flatbuffers::rehasher_function_t *_rehasher) {
  (void)_rehasher;
  (void)_o;
  struct _VectorArgs { flatbuffers::FlatBufferBuilder *__fbb; const PlainLabelMetaT* __o; const flatbuffers::rehasher_function_t *__rehasher; } _va = { &_fbb, _o, _rehasher}; (void)_va;
  auto _numClasses = _o->numClasses;
  return CreatePlainLabelMeta(
      _fbb,
      _numClasses);
}

inline const flatbuffers::TypeTable *PlainLabelMetaTypeTable() {
  static const flatbuffers::TypeCode type_codes[] = {
    { flatbuffers::ET_INT, 0, -1 }
  };
  static const flatbuffers::TypeTable tt = {
    flatbuffers::ST_TABLE, 1, type_codes, nullptr, nullptr, nullptr
  };
  return &tt;
}

inline const PlainLabelMeta *GetPlainLabelMeta(const void *buf) {
  return flatbuffers::GetRoot<PlainLabelMeta>(buf);
}

inline const PlainLabelMeta *GetSizePrefixedPlainLabelMeta(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<PlainLabelMeta>(buf);
}

inline PlainLabelMeta *GetMutablePlainLabelMeta(void *buf) {
  return flatbuffers::GetMutableRoot<PlainLabelMeta>(buf);
}

inline bool VerifyPlainLabelMetaBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<PlainLabelMeta>(nullptr);
}

inline bool VerifySizePrefixedPlainLabelMetaBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<PlainLabelMeta>(nullptr);
}

inline void FinishPlainLabelMetaBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainLabelMeta> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedPlainLabelMetaBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainLabelMeta> root) {
  fbb.FinishSizePrefixed(root);
}

inline std::unique_ptr<PlainLabelMetaT> UnPackPlainLabelMeta(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<PlainLabelMetaT>(GetPlainLabelMeta(buf)->UnPack(res));
}

inline std::unique_ptr<PlainLabelMetaT> UnPackSizePrefixedPlainLabelMeta(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<PlainLabelMetaT>(GetSizePrefixedPlainLabelMeta(buf)->UnPack(res));
}

#endif  // FLATBUFFERS_GENERATED_PLAINLABELMETA_H_
