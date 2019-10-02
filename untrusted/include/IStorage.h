#pragma once
#include <cstddef>

enum IntermediateStorageTypes {
  StorageOnLinkedList,
  StorageOnMap,
  StorageOnFile,
};

class IBasicStorage {
public:
  virtual ~IBasicStorage() = default;
  virtual void Save(size_t record_id) const = 0;
  virtual void Load(size_t record_id) const = 0;
protected:
    IntermediateStorageTypes storageType_;
};