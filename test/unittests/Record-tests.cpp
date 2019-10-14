#include "Record/ImageRecord.h"
#include "Record/ImageWithLabelRecord.h"

#include "gtest/gtest.h"

namespace {
  using namespace sgx::common;

  class ImageRecordTests : public ::testing::Test {
    protected:
    void
    SetUp() override {
      test_image_sizes = {{28, 28, 3}, {256, 256, 3}, {224, 224, 3}};
    }

    void
    TearDown() override {
    }
    std::vector<std::array<std::size_t, 3>> test_image_sizes;
  };
  TEST_F(ImageRecordTests, DefaultConstructor) {
    for (const auto& t : test_image_sizes) {
      ImageRecord rec(t[0], t[1], t[2]);
      ASSERT_EQ(rec.getRecordSizeInBytes(),
                (t[0] * t[1] * t[2] * sizeof(float)));
      ASSERT_EQ(rec.getRecordSizeInBytes(), rec.serializeFromThis().size());
    }
  }

  //   TEST_F(ImageRecordTests, CopyConstructor) {
  //     using namespace sgx::common;
  //     for (const auto& t : test_image_sizes) {
  //       ImageRecord make_copy(t[0], t[1], t[2]);
  //       ImageRecord rec(make_copy);
  //       ASSERT_EQ(rec.getRecordSizeInBytes(),
  //                 (t[0] * t[1] * t[2] * sizeof(float)));
  //       ASSERT_EQ(rec.getRecordSizeInBytes(),
  //       rec.serializeFromThis().size());
  //     }
  //   }

  //   TEST_F(ImageRecordTests, CopyAssignment) {
  //     using namespace sgx::common;
  //     for (const auto& t : test_image_sizes) {
  //       ImageRecord make_copy(t[0], t[1], t[2]);
  //       ImageRecord rec(10,7,4);
  //       rec = make_copy;
  //       ASSERT_EQ(rec.getRecordSizeInBytes(),
  //                 (t[0] * t[1] * t[2] * sizeof(float)));
  //       ASSERT_EQ(rec.getRecordSizeInBytes(),
  //       rec.serializeFromThis().size());
  //     }
  //   }

  TEST_F(ImageRecordTests, MoveConstructor) {
    for (const auto& t : test_image_sizes) {
      ImageRecord rec(ImageRecord(t[0], t[1], t[2]));
      ASSERT_EQ(rec.getRecordSizeInBytes(),
                (t[0] * t[1] * t[2] * sizeof(float)));
      ASSERT_EQ(rec.getRecordSizeInBytes(), rec.serializeFromThis().size());
    }
  }

//   TEST_F(ImageRecordTests, MoveAssignment) {
//     for (const auto& t : test_image_sizes) {
//       ImageRecord rec(16, 8, 9);
//       rec = ImageRecord(t[0], t[1], t[2]);
//       ASSERT_EQ(rec.getRecordSizeInBytes(),
//                 (t[0] * t[1] * t[2] * sizeof(float)));
//       ASSERT_EQ(rec.getRecordSizeInBytes(), rec.serializeFromThis().size());
//     }
//   }

  TEST_F(ImageRecordTests, SerializeAndUnserialize) {
    std::srand(std::time(nullptr));
    size_t ind = 0;
    for (const auto& t : test_image_sizes) {
      ImageRecord rec(t[0], t[1], t[2]);
      auto        serialized = rec.serializeFromThis();
      // some random change to the vector
      for (size_t i = 0; i < serialized.size() / 2; ++i) {
        ind             = ((size_t)std::rand()) % (serialized.size());
        serialized[ind] = ((uint8_t)std::rand()) % 255;
      }
      rec.unSerializeIntoThis(serialized);
      auto new_serialized = rec.serializeFromThis();
      ASSERT_EQ(serialized.size(), new_serialized.size());
      for (size_t i = 0; i < serialized.size(); ++i) {
        ASSERT_EQ(serialized[i], new_serialized[i]);
      }
    }
  }

  class ImageWLabelRecordTests : public ::testing::Test {
    protected:
    void
    SetUp() override {
      test_image_sizes = {{28, 28, 3}, {256, 256, 3}, {224, 224, 3}};
      test_num_classes = {10, 1000, 500};
      for (const auto& t : test_image_sizes) {
        test_images.push_back(
            std::make_unique<sgx::common::ImageRecord>(t[0], t[1], t[2]));
      }
    }

    void
    TearDown() override {
    }
    std::vector<std::array<std::size_t, 3>>                test_image_sizes;
    std::vector<std::unique_ptr<sgx::common::ImageRecord>> test_images;
    std::vector<int>                                       test_num_classes;
  };

  TEST_F(ImageWLabelRecordTests, DefaultConstructor) {
    for (size_t i = 0; i < test_images.size(); ++i) {
      ImageWLabelRecord rec(test_num_classes[i], std::move(test_images[i]));
      ASSERT_EQ(rec.getRecordSizeInBytes(),
                ((test_image_sizes[i][0] * test_image_sizes[i][1]
                  * test_image_sizes[i][2])
                 + test_num_classes[i])
                    * (sizeof(float)));
      ASSERT_EQ(rec.getRecordSizeInBytes(), rec.serializeFromThis().size());
    }
  }

  //   TEST_F(ImageWLabelRecordTests, CopyConstructor) {
  //     using namespace sgx::common;
  //     for (size_t i = 0; i < test_images.size(); ++i) {
  //       ImageWLabelRecord make_copy(test_num_classes[i],
  //       std::move(test_images[i])); ImageWLabelRecord rec(make_copy);

  //       ASSERT_EQ(rec.getRecordSizeInBytes(),
  //                 ((test_image_sizes[i][0] * test_image_sizes[i][1] *
  //                 test_image_sizes[i][2]) +
  //                 test_num_classes[i])*(sizeof(float)));
  //       ASSERT_EQ(rec.getRecordSizeInBytes(),
  //       rec.serializeFromThis().size());
  //     }
  //   }

  TEST_F(ImageWLabelRecordTests, MoveConstructor) {
    for (size_t i = 0; i < test_images.size(); ++i) {
      ImageWLabelRecord rec
          = ImageWLabelRecord(test_num_classes[i], std::move(test_images[i]));

      ASSERT_EQ(rec.getRecordSizeInBytes(),
                ((test_image_sizes[i][0] * test_image_sizes[i][1]
                  * test_image_sizes[i][2])
                 + test_num_classes[i])
                    * (sizeof(float)));
      ASSERT_EQ(rec.getRecordSizeInBytes(), rec.serializeFromThis().size());
    }
  }

  TEST_F(ImageWLabelRecordTests, SerializeAndUnserialize) {
    std::srand(std::time(nullptr));
    size_t ind = 0;
    for (size_t i = 0; i < test_images.size(); ++i) {
      ImageWLabelRecord rec(test_num_classes[i], std::move(test_images[i]));
      auto              serialized = rec.serializeFromThis();
      // some random change to the vector
      for (size_t i = 0; i < serialized.size() / 2; ++i) {
        ind             = ((size_t)std::rand()) % (serialized.size());
        serialized[ind] = ((uint8_t)std::rand()) % 255;
      }
      rec.unSerializeIntoThis(serialized);
      auto new_serialized = rec.serializeFromThis();
      ASSERT_EQ(serialized.size(), new_serialized.size());
      for (size_t i = 0; i < serialized.size(); ++i) {
        ASSERT_EQ(serialized[i], new_serialized[i]);
      }

      std::fill(serialized.begin(), serialized.end(), 0);
      std::fill(new_serialized.begin(), new_serialized.end(), 0);

      for (size_t i = 0; i < new_serialized.size() / 2; ++i) {
        ind                 = ((size_t)std::rand()) % (new_serialized.size());
        new_serialized[ind] = ((uint8_t)std::rand()) % 255;
      }
      rec.unSerializeIntoThis(&new_serialized[0], 0, new_serialized.size());
      rec.serializeFromThis(&serialized[0], 0, serialized.size());
      ASSERT_EQ(serialized.size(), new_serialized.size());
      for (size_t i = 0; i < serialized.size(); ++i) {
        ASSERT_EQ(serialized[i], new_serialized[i]);
      }
    }
  }
}  // namespace