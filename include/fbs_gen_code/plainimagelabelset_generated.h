// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_PLAINIMAGELABELSET_H_
#define FLATBUFFERS_GENERATED_PLAINIMAGELABELSET_H_

#include "flatbuffers/flatbuffers.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 22 &&
              FLATBUFFERS_VERSION_MINOR == 11 &&
              FLATBUFFERS_VERSION_REVISION == 23,
             "Non-compatible flatbuffers version included");

#include "plainimagelabel_generated.h"

struct PlainImageLabelSet;
struct PlainImageLabelSetBuilder;

struct PlainImageLabelSet FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef PlainImageLabelSetBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_IMAGES = 4
  };
  const flatbuffers::Vector<flatbuffers::Offset<PlainImageLabel>> *images() const {
    return GetPointer<const flatbuffers::Vector<flatbuffers::Offset<PlainImageLabel>> *>(VT_IMAGES);
  }
  flatbuffers::Vector<flatbuffers::Offset<PlainImageLabel>> *mutable_images() {
    return GetPointer<flatbuffers::Vector<flatbuffers::Offset<PlainImageLabel>> *>(VT_IMAGES);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_IMAGES) &&
           verifier.VerifyVector(images()) &&
           verifier.VerifyVectorOfTables(images()) &&
           verifier.EndTable();
  }
};

struct PlainImageLabelSetBuilder {
  typedef PlainImageLabelSet Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_images(flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<PlainImageLabel>>> images) {
    fbb_.AddOffset(PlainImageLabelSet::VT_IMAGES, images);
  }
  explicit PlainImageLabelSetBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<PlainImageLabelSet> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<PlainImageLabelSet>(end);
    fbb_.Required(o, PlainImageLabelSet::VT_IMAGES);
    return o;
  }
};

inline flatbuffers::Offset<PlainImageLabelSet> CreatePlainImageLabelSet(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<PlainImageLabel>>> images = 0) {
  PlainImageLabelSetBuilder builder_(_fbb);
  builder_.add_images(images);
  return builder_.Finish();
}

inline flatbuffers::Offset<PlainImageLabelSet> CreatePlainImageLabelSetDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<flatbuffers::Offset<PlainImageLabel>> *images = nullptr) {
  auto images__ = images ? _fbb.CreateVector<flatbuffers::Offset<PlainImageLabel>>(*images) : 0;
  return CreatePlainImageLabelSet(
      _fbb,
      images__);
}

inline const PlainImageLabelSet *GetPlainImageLabelSet(const void *buf) {
  return flatbuffers::GetRoot<PlainImageLabelSet>(buf);
}

inline const PlainImageLabelSet *GetSizePrefixedPlainImageLabelSet(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<PlainImageLabelSet>(buf);
}

inline PlainImageLabelSet *GetMutablePlainImageLabelSet(void *buf) {
  return flatbuffers::GetMutableRoot<PlainImageLabelSet>(buf);
}

inline PlainImageLabelSet *GetMutableSizePrefixedPlainImageLabelSet(void *buf) {
  return flatbuffers::GetMutableSizePrefixedRoot<PlainImageLabelSet>(buf);
}

inline bool VerifyPlainImageLabelSetBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<PlainImageLabelSet>(nullptr);
}

inline bool VerifySizePrefixedPlainImageLabelSetBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<PlainImageLabelSet>(nullptr);
}

inline void FinishPlainImageLabelSetBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageLabelSet> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedPlainImageLabelSetBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageLabelSet> root) {
  fbb.FinishSizePrefixed(root);
}

#endif  // FLATBUFFERS_GENERATED_PLAINIMAGELABELSET_H_
