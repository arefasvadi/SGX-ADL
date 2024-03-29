// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_PLAINIMAGELABELMETA_H_
#define FLATBUFFERS_GENERATED_PLAINIMAGELABELMETA_H_

#include "flatbuffers/flatbuffers.h"

struct PlainImageMeta;
struct PlainImageMetaT;

struct PlainLabelMeta;
struct PlainLabelMetaT;

struct PlainImageLabelMeta;
struct PlainImageLabelMetaT;

inline const flatbuffers::TypeTable *PlainImageMetaTypeTable();

inline const flatbuffers::TypeTable *PlainLabelMetaTypeTable();

inline const flatbuffers::TypeTable *PlainImageLabelMetaTypeTable();

struct PlainImageMetaT : public flatbuffers::NativeTable {
  typedef PlainImageMeta TableType;
  int32_t width;
  int32_t height;
  int32_t channels;
  PlainImageMetaT()
      : width(0),
        height(0),
        channels(0) {
  }
};

struct PlainImageMeta FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef PlainImageMetaT NativeTableType;
  static const flatbuffers::TypeTable *MiniReflectTypeTable() {
    return PlainImageMetaTypeTable();
  }
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_WIDTH = 4,
    VT_HEIGHT = 6,
    VT_CHANNELS = 8
  };
  int32_t width() const {
    return GetField<int32_t>(VT_WIDTH, 0);
  }
  bool mutate_width(int32_t _width) {
    return SetField<int32_t>(VT_WIDTH, _width, 0);
  }
  int32_t height() const {
    return GetField<int32_t>(VT_HEIGHT, 0);
  }
  bool mutate_height(int32_t _height) {
    return SetField<int32_t>(VT_HEIGHT, _height, 0);
  }
  int32_t channels() const {
    return GetField<int32_t>(VT_CHANNELS, 0);
  }
  bool mutate_channels(int32_t _channels) {
    return SetField<int32_t>(VT_CHANNELS, _channels, 0);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<int32_t>(verifier, VT_WIDTH) &&
           VerifyField<int32_t>(verifier, VT_HEIGHT) &&
           VerifyField<int32_t>(verifier, VT_CHANNELS) &&
           verifier.EndTable();
  }
  PlainImageMetaT *UnPack(const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  void UnPackTo(PlainImageMetaT *_o, const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  static flatbuffers::Offset<PlainImageMeta> Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageMetaT* _o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);
};

struct PlainImageMetaBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_width(int32_t width) {
    fbb_.AddElement<int32_t>(PlainImageMeta::VT_WIDTH, width, 0);
  }
  void add_height(int32_t height) {
    fbb_.AddElement<int32_t>(PlainImageMeta::VT_HEIGHT, height, 0);
  }
  void add_channels(int32_t channels) {
    fbb_.AddElement<int32_t>(PlainImageMeta::VT_CHANNELS, channels, 0);
  }
  explicit PlainImageMetaBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  PlainImageMetaBuilder &operator=(const PlainImageMetaBuilder &);
  flatbuffers::Offset<PlainImageMeta> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<PlainImageMeta>(end);
    return o;
  }
};

inline flatbuffers::Offset<PlainImageMeta> CreatePlainImageMeta(
    flatbuffers::FlatBufferBuilder &_fbb,
    int32_t width = 0,
    int32_t height = 0,
    int32_t channels = 0) {
  PlainImageMetaBuilder builder_(_fbb);
  builder_.add_channels(channels);
  builder_.add_height(height);
  builder_.add_width(width);
  return builder_.Finish();
}

flatbuffers::Offset<PlainImageMeta> CreatePlainImageMeta(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageMetaT *_o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);

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

struct PlainImageLabelMetaT : public flatbuffers::NativeTable {
  typedef PlainImageLabelMeta TableType;
  std::unique_ptr<PlainImageMetaT> image_meta;
  std::unique_ptr<PlainLabelMetaT> label_meta;
  PlainImageLabelMetaT() {
  }
};

struct PlainImageLabelMeta FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef PlainImageLabelMetaT NativeTableType;
  static const flatbuffers::TypeTable *MiniReflectTypeTable() {
    return PlainImageLabelMetaTypeTable();
  }
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_IMAGE_META = 4,
    VT_LABEL_META = 6
  };
  const PlainImageMeta *image_meta() const {
    return GetPointer<const PlainImageMeta *>(VT_IMAGE_META);
  }
  PlainImageMeta *mutable_image_meta() {
    return GetPointer<PlainImageMeta *>(VT_IMAGE_META);
  }
  const PlainLabelMeta *label_meta() const {
    return GetPointer<const PlainLabelMeta *>(VT_LABEL_META);
  }
  PlainLabelMeta *mutable_label_meta() {
    return GetPointer<PlainLabelMeta *>(VT_LABEL_META);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_IMAGE_META) &&
           verifier.VerifyTable(image_meta()) &&
           VerifyOffset(verifier, VT_LABEL_META) &&
           verifier.VerifyTable(label_meta()) &&
           verifier.EndTable();
  }
  PlainImageLabelMetaT *UnPack(const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  void UnPackTo(PlainImageLabelMetaT *_o, const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  static flatbuffers::Offset<PlainImageLabelMeta> Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelMetaT* _o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);
};

struct PlainImageLabelMetaBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_image_meta(flatbuffers::Offset<PlainImageMeta> image_meta) {
    fbb_.AddOffset(PlainImageLabelMeta::VT_IMAGE_META, image_meta);
  }
  void add_label_meta(flatbuffers::Offset<PlainLabelMeta> label_meta) {
    fbb_.AddOffset(PlainImageLabelMeta::VT_LABEL_META, label_meta);
  }
  explicit PlainImageLabelMetaBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  PlainImageLabelMetaBuilder &operator=(const PlainImageLabelMetaBuilder &);
  flatbuffers::Offset<PlainImageLabelMeta> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<PlainImageLabelMeta>(end);
    return o;
  }
};

inline flatbuffers::Offset<PlainImageLabelMeta> CreatePlainImageLabelMeta(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<PlainImageMeta> image_meta = 0,
    flatbuffers::Offset<PlainLabelMeta> label_meta = 0) {
  PlainImageLabelMetaBuilder builder_(_fbb);
  builder_.add_label_meta(label_meta);
  builder_.add_image_meta(image_meta);
  return builder_.Finish();
}

flatbuffers::Offset<PlainImageLabelMeta> CreatePlainImageLabelMeta(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelMetaT *_o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);

inline PlainImageMetaT *PlainImageMeta::UnPack(const flatbuffers::resolver_function_t *_resolver) const {
  auto _o = new PlainImageMetaT();
  UnPackTo(_o, _resolver);
  return _o;
}

inline void PlainImageMeta::UnPackTo(PlainImageMetaT *_o, const flatbuffers::resolver_function_t *_resolver) const {
  (void)_o;
  (void)_resolver;
  { auto _e = width(); _o->width = _e; }
  { auto _e = height(); _o->height = _e; }
  { auto _e = channels(); _o->channels = _e; }
}

inline flatbuffers::Offset<PlainImageMeta> PlainImageMeta::Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageMetaT* _o, const flatbuffers::rehasher_function_t *_rehasher) {
  return CreatePlainImageMeta(_fbb, _o, _rehasher);
}

inline flatbuffers::Offset<PlainImageMeta> CreatePlainImageMeta(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageMetaT *_o, const flatbuffers::rehasher_function_t *_rehasher) {
  (void)_rehasher;
  (void)_o;
  struct _VectorArgs { flatbuffers::FlatBufferBuilder *__fbb; const PlainImageMetaT* __o; const flatbuffers::rehasher_function_t *__rehasher; } _va = { &_fbb, _o, _rehasher}; (void)_va;
  auto _width = _o->width;
  auto _height = _o->height;
  auto _channels = _o->channels;
  return CreatePlainImageMeta(
      _fbb,
      _width,
      _height,
      _channels);
}

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

inline PlainImageLabelMetaT *PlainImageLabelMeta::UnPack(const flatbuffers::resolver_function_t *_resolver) const {
  auto _o = new PlainImageLabelMetaT();
  UnPackTo(_o, _resolver);
  return _o;
}

inline void PlainImageLabelMeta::UnPackTo(PlainImageLabelMetaT *_o, const flatbuffers::resolver_function_t *_resolver) const {
  (void)_o;
  (void)_resolver;
  { auto _e = image_meta(); if (_e) _o->image_meta = std::unique_ptr<PlainImageMetaT>(_e->UnPack(_resolver)); }
  { auto _e = label_meta(); if (_e) _o->label_meta = std::unique_ptr<PlainLabelMetaT>(_e->UnPack(_resolver)); }
}

inline flatbuffers::Offset<PlainImageLabelMeta> PlainImageLabelMeta::Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelMetaT* _o, const flatbuffers::rehasher_function_t *_rehasher) {
  return CreatePlainImageLabelMeta(_fbb, _o, _rehasher);
}

inline flatbuffers::Offset<PlainImageLabelMeta> CreatePlainImageLabelMeta(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelMetaT *_o, const flatbuffers::rehasher_function_t *_rehasher) {
  (void)_rehasher;
  (void)_o;
  struct _VectorArgs { flatbuffers::FlatBufferBuilder *__fbb; const PlainImageLabelMetaT* __o; const flatbuffers::rehasher_function_t *__rehasher; } _va = { &_fbb, _o, _rehasher}; (void)_va;
  auto _image_meta = _o->image_meta ? CreatePlainImageMeta(_fbb, _o->image_meta.get(), _rehasher) : 0;
  auto _label_meta = _o->label_meta ? CreatePlainLabelMeta(_fbb, _o->label_meta.get(), _rehasher) : 0;
  return CreatePlainImageLabelMeta(
      _fbb,
      _image_meta,
      _label_meta);
}

inline const flatbuffers::TypeTable *PlainImageMetaTypeTable() {
  static const flatbuffers::TypeCode type_codes[] = {
    { flatbuffers::ET_INT, 0, -1 },
    { flatbuffers::ET_INT, 0, -1 },
    { flatbuffers::ET_INT, 0, -1 }
  };
  static const flatbuffers::TypeTable tt = {
    flatbuffers::ST_TABLE, 3, type_codes, nullptr, nullptr, nullptr
  };
  return &tt;
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

inline const flatbuffers::TypeTable *PlainImageLabelMetaTypeTable() {
  static const flatbuffers::TypeCode type_codes[] = {
    { flatbuffers::ET_SEQUENCE, 0, 0 },
    { flatbuffers::ET_SEQUENCE, 0, 1 }
  };
  static const flatbuffers::TypeFunction type_refs[] = {
    PlainImageMetaTypeTable,
    PlainLabelMetaTypeTable
  };
  static const flatbuffers::TypeTable tt = {
    flatbuffers::ST_TABLE, 2, type_codes, type_refs, nullptr, nullptr
  };
  return &tt;
}

inline const PlainImageLabelMeta *GetPlainImageLabelMeta(const void *buf) {
  return flatbuffers::GetRoot<PlainImageLabelMeta>(buf);
}

inline const PlainImageLabelMeta *GetSizePrefixedPlainImageLabelMeta(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<PlainImageLabelMeta>(buf);
}

inline PlainImageLabelMeta *GetMutablePlainImageLabelMeta(void *buf) {
  return flatbuffers::GetMutableRoot<PlainImageLabelMeta>(buf);
}

inline bool VerifyPlainImageLabelMetaBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<PlainImageLabelMeta>(nullptr);
}

inline bool VerifySizePrefixedPlainImageLabelMetaBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<PlainImageLabelMeta>(nullptr);
}

inline void FinishPlainImageLabelMetaBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageLabelMeta> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedPlainImageLabelMetaBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageLabelMeta> root) {
  fbb.FinishSizePrefixed(root);
}

inline std::unique_ptr<PlainImageLabelMetaT> UnPackPlainImageLabelMeta(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<PlainImageLabelMetaT>(GetPlainImageLabelMeta(buf)->UnPack(res));
}

inline std::unique_ptr<PlainImageLabelMetaT> UnPackSizePrefixedPlainImageLabelMeta(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<PlainImageLabelMetaT>(GetSizePrefixedPlainImageLabelMeta(buf)->UnPack(res));
}

#endif  // FLATBUFFERS_GENERATED_PLAINIMAGELABELMETA_H_
