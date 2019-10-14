// #pragma once

// namespace sgx {
//   namespace common {

//     template <typename T>
//     class IStorage {
//       public:
//       virtual ~IStorage() = 0;

//       virtual const T&
//       getItemAt(uint64_t index) const = 0;

//       virtual T
//       getItemAt(uint64_t index) const = 0;

//       virtual void
//       setItemAt(uint64_t index, const T& item)
//           = 0;

//       virtual T
//       removeItemAt(uint64_t index)
//           = 0;

//       virtual void
//       removeItemAt(uint64_t index)
//           = 0;

//       virtual const size_t
//       totalItems()
//           = 0;

//       protected:
//       private:
//     };

//     class vectorStorage

//   }  // namespace common
// }  // namespace sgx