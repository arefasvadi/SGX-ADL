// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_ENUMS_H_
#define FLATBUFFERS_GENERATED_ENUMS_H_

#include "flatbuffers/flatbuffers.h"

enum EnumSecurityType {
  EnumSecurityType_integrity = 0,
  EnumSecurityType_privacy_integrity = 1,
  EnumSecurityType_MIN = EnumSecurityType_integrity,
  EnumSecurityType_MAX = EnumSecurityType_privacy_integrity
};

inline const EnumSecurityType (&EnumValuesEnumSecurityType())[2] {
  static const EnumSecurityType values[] = {
    EnumSecurityType_integrity,
    EnumSecurityType_privacy_integrity
  };
  return values;
}

inline const char * const *EnumNamesEnumSecurityType() {
  static const char * const names[3] = {
    "integrity",
    "privacy_integrity",
    nullptr
  };
  return names;
}

inline const char *EnumNameEnumSecurityType(EnumSecurityType e) {
  if (e < EnumSecurityType_integrity || e > EnumSecurityType_privacy_integrity) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesEnumSecurityType()[index];
}

enum EnumComputationTaskType {
  EnumComputationTaskType_training = 0,
  EnumComputationTaskType_prediction = 1,
  EnumComputationTaskType_MIN = EnumComputationTaskType_training,
  EnumComputationTaskType_MAX = EnumComputationTaskType_prediction
};

inline const EnumComputationTaskType (&EnumValuesEnumComputationTaskType())[2] {
  static const EnumComputationTaskType values[] = {
    EnumComputationTaskType_training,
    EnumComputationTaskType_prediction
  };
  return values;
}

inline const char * const *EnumNamesEnumComputationTaskType() {
  static const char * const names[3] = {
    "training",
    "prediction",
    nullptr
  };
  return names;
}

inline const char *EnumNameEnumComputationTaskType(EnumComputationTaskType e) {
  if (e < EnumComputationTaskType_training || e > EnumComputationTaskType_prediction) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesEnumComputationTaskType()[index];
}

inline const flatbuffers::TypeTable *EnumSecurityTypeTypeTable() {
  static const flatbuffers::TypeCode type_codes[] = {
    { flatbuffers::ET_SHORT, 0, 0 },
    { flatbuffers::ET_SHORT, 0, 0 }
  };
  static const flatbuffers::TypeFunction type_refs[] = {
    EnumSecurityTypeTypeTable
  };
  static const flatbuffers::TypeTable tt = {
    flatbuffers::ST_ENUM, 2, type_codes, type_refs, nullptr, nullptr
  };
  return &tt;
}

inline const flatbuffers::TypeTable *EnumComputationTaskTypeTypeTable() {
  static const flatbuffers::TypeCode type_codes[] = {
    { flatbuffers::ET_SHORT, 0, 0 },
    { flatbuffers::ET_SHORT, 0, 0 }
  };
  static const flatbuffers::TypeFunction type_refs[] = {
    EnumComputationTaskTypeTypeTable
  };
  static const flatbuffers::TypeTable tt = {
    flatbuffers::ST_ENUM, 2, type_codes, type_refs, nullptr, nullptr
  };
  return &tt;
}

#endif  // FLATBUFFERS_GENERATED_ENUMS_H_
