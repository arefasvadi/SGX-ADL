// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_PLAINIMAGESET_H_
#define FLATBUFFERS_GENERATED_PLAINIMAGESET_H_

#include "flatbuffers/flatbuffers.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 22 &&
              FLATBUFFERS_VERSION_MINOR == 11 &&
              FLATBUFFERS_VERSION_REVISION == 23,
             "Non-compatible flatbuffers version included");

#include "plainimage_generated.h"

struct PlainImageSet;
struct PlainImageSetBuilder;

struct PlainImageSet FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef PlainImageSetBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_IMAGES = 4
  };
  const flatbuffers::Vector<flatbuffers::Offset<PlainImage>> *images() const {
    return GetPointer<const flatbuffers::Vector<flatbuffers::Offset<PlainImage>> *>(VT_IMAGES);
  }
  flatbuffers::Vector<flatbuffers::Offset<PlainImage>> *mutable_images() {
    return GetPointer<flatbuffers::Vector<flatbuffers::Offset<PlainImage>> *>(VT_IMAGES);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_IMAGES) &&
           verifier.VerifyVector(images()) &&
           verifier.VerifyVectorOfTables(images()) &&
           verifier.EndTable();
  }
};

struct PlainImageSetBuilder {
  typedef PlainImageSet Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_images(flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<PlainImage>>> images) {
    fbb_.AddOffset(PlainImageSet::VT_IMAGES, images);
  }
  explicit PlainImageSetBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<PlainImageSet> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<PlainImageSet>(end);
    fbb_.Required(o, PlainImageSet::VT_IMAGES);
    return o;
  }
};

inline flatbuffers::Offset<PlainImageSet> CreatePlainImageSet(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<PlainImage>>> images = 0) {
  PlainImageSetBuilder builder_(_fbb);
  builder_.add_images(images);
  return builder_.Finish();
}

inline flatbuffers::Offset<PlainImageSet> CreatePlainImageSetDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<flatbuffers::Offset<PlainImage>> *images = nullptr) {
  auto images__ = images ? _fbb.CreateVector<flatbuffers::Offset<PlainImage>>(*images) : 0;
  return CreatePlainImageSet(
      _fbb,
      images__);
}

inline const PlainImageSet *GetPlainImageSet(const void *buf) {
  return flatbuffers::GetRoot<PlainImageSet>(buf);
}

inline const PlainImageSet *GetSizePrefixedPlainImageSet(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<PlainImageSet>(buf);
}

inline PlainImageSet *GetMutablePlainImageSet(void *buf) {
  return flatbuffers::GetMutableRoot<PlainImageSet>(buf);
}

inline PlainImageSet *GetMutableSizePrefixedPlainImageSet(void *buf) {
  return flatbuffers::GetMutableSizePrefixedRoot<PlainImageSet>(buf);
}

inline bool VerifyPlainImageSetBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<PlainImageSet>(nullptr);
}

inline bool VerifySizePrefixedPlainImageSetBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<PlainImageSet>(nullptr);
}

inline void FinishPlainImageSetBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageSet> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedPlainImageSetBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<PlainImageSet> root) {
  fbb.FinishSizePrefixed(root);
}

#endif  // FLATBUFFERS_GENERATED_PLAINIMAGESET_H_
