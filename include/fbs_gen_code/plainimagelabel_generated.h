// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_PLAINIMAGELABEL_H_
#define FLATBUFFERS_GENERATED_PLAINIMAGELABEL_H_

#include "flatbuffers/flatbuffers.h"

struct PlainImageLabel;
struct PlainImageLabelT;

inline const flatbuffers::TypeTable *PlainImageLabelTypeTable();

struct PlainImageLabelT : public flatbuffers::NativeTable {
  typedef PlainImageLabel TableType;
  std::vector<float> img_content;
  std::vector<float> label_content;
  PlainImageLabelT() {
  }
};

struct PlainImageLabel FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef PlainImageLabelT NativeTableType;
  static const flatbuffers::TypeTable *MiniReflectTypeTable() {
    return PlainImageLabelTypeTable();
  }
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_IMG_CONTENT = 4,
    VT_LABEL_CONTENT = 6
  };
  const flatbuffers::Vector<float> *img_content() const {
    return GetPointer<const flatbuffers::Vector<float> *>(VT_IMG_CONTENT);
  }
  flatbuffers::Vector<float> *mutable_img_content() {
    return GetPointer<flatbuffers::Vector<float> *>(VT_IMG_CONTENT);
  }
  const flatbuffers::Vector<float> *label_content() const {
    return GetPointer<const flatbuffers::Vector<float> *>(VT_LABEL_CONTENT);
  }
  flatbuffers::Vector<float> *mutable_label_content() {
    return GetPointer<flatbuffers::Vector<float> *>(VT_LABEL_CONTENT);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_IMG_CONTENT) &&
           verifier.VerifyVector(img_content()) &&
           VerifyOffsetRequired(verifier, VT_LABEL_CONTENT) &&
           verifier.VerifyVector(label_content()) &&
           verifier.EndTable();
  }
  PlainImageLabelT *UnPack(const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  void UnPackTo(PlainImageLabelT *_o, const flatbuffers::resolver_function_t *_resolver = nullptr) const;
  static flatbuffers::Offset<PlainImageLabel> Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelT* _o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);
};

struct PlainImageLabelBuilder {
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_img_content(flatbuffers::Offset<flatbuffers::Vector<float>> img_content) {
    fbb_.AddOffset(PlainImageLabel::VT_IMG_CONTENT, img_content);
  }
  void add_label_content(flatbuffers::Offset<flatbuffers::Vector<float>> label_content) {
    fbb_.AddOffset(PlainImageLabel::VT_LABEL_CONTENT, label_content);
  }
  explicit PlainImageLabelBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  PlainImageLabelBuilder &operator=(const PlainImageLabelBuilder &);
  flatbuffers::Offset<PlainImageLabel> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<PlainImageLabel>(end);
    fbb_.Required(o, PlainImageLabel::VT_IMG_CONTENT);
    fbb_.Required(o, PlainImageLabel::VT_LABEL_CONTENT);
    return o;
  }
};

inline flatbuffers::Offset<PlainImageLabel> CreatePlainImageLabel(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<float>> img_content = 0,
    flatbuffers::Offset<flatbuffers::Vector<float>> label_content = 0) {
  PlainImageLabelBuilder builder_(_fbb);
  builder_.add_label_content(label_content);
  builder_.add_img_content(img_content);
  return builder_.Finish();
}

inline flatbuffers::Offset<PlainImageLabel> CreatePlainImageLabelDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<float> *img_content = nullptr,
    const std::vector<float> *label_content = nullptr) {
  auto img_content__ = img_content ? _fbb.CreateVector<float>(*img_content) : 0;
  auto label_content__ = label_content ? _fbb.CreateVector<float>(*label_content) : 0;
  return CreatePlainImageLabel(
      _fbb,
      img_content__,
      label_content__);
}

flatbuffers::Offset<PlainImageLabel> CreatePlainImageLabel(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelT *_o, const flatbuffers::rehasher_function_t *_rehasher = nullptr);

inline PlainImageLabelT *PlainImageLabel::UnPack(const flatbuffers::resolver_function_t *_resolver) const {
  auto _o = new PlainImageLabelT();
  UnPackTo(_o, _resolver);
  return _o;
}

inline void PlainImageLabel::UnPackTo(PlainImageLabelT *_o, const flatbuffers::resolver_function_t *_resolver) const {
  (void)_o;
  (void)_resolver;
  { auto _e = img_content(); if (_e) { _o->img_content.resize(_e->size()); for (flatbuffers::uoffset_t _i = 0; _i < _e->size(); _i++) { _o->img_content[_i] = _e->Get(_i); } } }
  { auto _e = label_content(); if (_e) { _o->label_content.resize(_e->size()); for (flatbuffers::uoffset_t _i = 0; _i < _e->size(); _i++) { _o->label_content[_i] = _e->Get(_i); } } }
}

inline flatbuffers::Offset<PlainImageLabel> PlainImageLabel::Pack(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelT* _o, const flatbuffers::rehasher_function_t *_rehasher) {
  return CreatePlainImageLabel(_fbb, _o, _rehasher);
}

inline flatbuffers::Offset<PlainImageLabel> CreatePlainImageLabel(flatbuffers::FlatBufferBuilder &_fbb, const PlainImageLabelT *_o, const flatbuffers::rehasher_function_t *_rehasher) {
  (void)_rehasher;
  (void)_o;
  struct _VectorArgs { flatbuffers::FlatBufferBuilder *__fbb; const PlainImageLabelT* __o; const flatbuffers::rehasher_function_t *__rehasher; } _va = { &_fbb, _o, _rehasher}; (void)_va;
  auto _img_content = _fbb.CreateVector(_o->img_content);
  auto _label_content = _fbb.CreateVector(_o->label_content);
  return CreatePlainImageLabel(
      _fbb,
      _img_content,
      _label_content);
}

inline const flatbuffers::TypeTable *PlainImageLabelTypeTable() {
  static const flatbuffers::TypeCode type_codes[] = {
    { flatbuffers::ET_FLOAT, 1, -1 },
    { flatbuffers::ET_FLOAT, 1, -1 }
  };
  static const flatbuffers::TypeTable tt = {
    flatbuffers::ST_TABLE, 2, type_codes, nullptr, nullptr, nullptr
  };
  return &tt;
}

inline const PlainImageLabel *GetPlainImageLabel(const void *buf) {
  return flatbuffers::GetRoot<PlainImageLabel>(buf);
}

inline const PlainImageLabel *GetSizePrefixedPlainImageLabel(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<PlainImageLabel>(buf);
}

inline PlainImageLabel *GetMutablePlainImageLabel(void *buf) {
  return flatbuffers::GetMutableRoot<PlainImageLabel>(buf);
}

inline bool VerifyPlainImageLabelBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<PlainImageLabel>(nullptr);
}

inline bool VerifySizePrefixedPlainImageLabelBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<PlainImageLabel>(nullptr);
}

inline void FinishPlainImageLabelBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageLabel> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedPlainImageLabelBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageLabel> root) {
  fbb.FinishSizePrefixed(root);
}

inline std::unique_ptr<PlainImageLabelT> UnPackPlainImageLabel(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<PlainImageLabelT>(GetPlainImageLabel(buf)->UnPack(res));
}

inline std::unique_ptr<PlainImageLabelT> UnPackSizePrefixedPlainImageLabel(
    const void *buf,
    const flatbuffers::resolver_function_t *res = nullptr) {
  return std::unique_ptr<PlainImageLabelT>(GetSizePrefixedPlainImageLabel(buf)->UnPack(res));
}

#endif  // FLATBUFFERS_GENERATED_PLAINIMAGELABEL_H_