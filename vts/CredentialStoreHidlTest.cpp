/*
**
** Copyright 2018, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/
#define LOG_TAG "identity_writeableCredential_hidl_test"

#include <log/log.h>
#include <android/hardware/identity_credential/1.0/IIdentityCredentialStore.h>
#include <android/hardware/identity_credential/1.0/types.h>
#include <VtsHalHidlTargetTestBase.h>
#include <VtsHalHidlTargetTestEnvBase.h>

using ::android::hardware::keymaster::capability::V1_0::CapabilityType;
using ::testing::VtsHalHidlTargetTestEnvBase;

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace test {

/******************************
 *     GENERAL CONSTANTS      *
 ******************************/
constexpr uint8_t kAesGcmIvSize = 12;
constexpr uint8_t kAesGcmTagSize = 16;
constexpr uint8_t kAesGcmKeySize = 16; // 128 bit keys
constexpr uint8_t kECKeySize = 32; // 128 bit keys

/******************************
 * TEST DATA FOR PROVISIONING *
 ******************************/
struct EntryData{
    EntryData(std::string nameSpace, std::string name, bool directlyAvailable)
        : nameSpace(nameSpace), name(name), directlyAvailable(directlyAvailable) {}
    EntryData(std::string nameSpace, std::string name, std::string string,
              bool directlyAvailable)
        : EntryData(nameSpace, name, directlyAvailable) {
        value.textString(string);
    }
    EntryData(std::string nameSpace, std::string name, vector<uint8_t> byteString,
              bool directlyAvailable)
        : EntryData(nameSpace, name, directlyAvailable) {
        value.byteString(byteString);
    }
    EntryData(std::string nameSpace, std::string name, bool boolVal,
              bool directlyAvailable)
        : EntryData(nameSpace, name, directlyAvailable) {
        value.booleanValue(boolVal);
    }
    EntryData(std::string nameSpace, std::string name, uint64_t intVal,
              bool directlyAvailable)
        : EntryData(nameSpace, name, directlyAvailable) {
        value.integer(intVal);
    }


    std::string nameSpace;
    std::string name;
    EntryValue value;
    bool directlyAvailable;
};

const EntryData testEntry1 {
    "PersonalData",
    "Last name",
    std::string("Turing"),
    false
};

const EntryData testEntry2 {
    "PersonalData",
    "Birth date",
    std::string("19120623"),
    false
};

const EntryData testEntry3 {
    "PersonalData",
    "First name",
    std::string("Alan"),
    false
};

const EntryData testEntry4 {
    "PersonalData",
    "Home address",
    std::string("Maida Vale, London, England"),
    false
};

const std::vector<std::pair<EntryData, hidl_vec<uint8_t>>> testEntries{
    {testEntry1, {1}},
    {testEntry2, {2}},
    {testEntry3, {3}},
    {testEntry4, {0, 1}}
};

struct TestProfile{
    uint8_t id;
    hidl_vec<uint8_t> readerAuthPubKey;
    uint64_t capabilityId;
    CapabilityType capabilityType;
    uint64_t timeout;
};

// Profile 1 (reader authentication)
const TestProfile testProfile1 = {0u,
                                  {0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
                                   0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
                                   0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F},
                                  0u,
                                  CapabilityType::NOT_APPLICABLE,
                                  0u};

// Profile 2 (user authentication)
const TestProfile testProfile2 = {1u, {}, 0x1234567890ABCDEF, CapabilityType::ANY, 100u};

// Profile 3 (user + reader authentication)
const TestProfile testProfile3 = {2u,
                                  {0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
                                   0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
                                   0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F},
                                  0x1234567890ABCDEF,
                                  CapabilityType::ANY,
                                  100u};

// Profile 4 (no authentication)
const TestProfile testProfile4 = {3u, {}, 0u, CapabilityType::NOT_APPLICABLE, 0u};

const std::vector<TestProfile> testProfiles {testProfile1, testProfile2, testProfile3, testProfile4};


class IdentityCredentialStoreHidlEnvironment : public VtsHalHidlTargetTestEnvBase {
  public:
    // get the test environment singleton
    static IdentityCredentialStoreHidlEnvironment* Instance() {
        static IdentityCredentialStoreHidlEnvironment* instance =
                new IdentityCredentialStoreHidlEnvironment;
        return instance;
    }
    virtual void registerTestServices() override {
        registerTestService<IIdentityCredentialStore>();
    }

  private:
    IdentityCredentialStoreHidlEnvironment() {}
};

// The main test class credential HIDL HAL.
class IdentityCredentialStoreHidlTest : public ::testing::VtsHalHidlTargetTestBase {
 public:
    virtual void SetUp() override {
        std::string serviceName =
            IdentityCredentialStoreHidlEnvironment::Instance()->getServiceName<IIdentityCredentialStore>("default");
        ASSERT_FALSE(serviceName.empty());

        credentialstore_ = ::testing::VtsHalHidlTargetTestBase::getService<IIdentityCredentialStore>(serviceName);

        ASSERT_NE(credentialstore_, nullptr);


        credentialstore_->getHardwareInformation([&](ResultCode hidl_error,
                                                    const hidl_string& credentialStoreName,
                                                    const hidl_string& credentialStoreAuthorName,
                                                    uint32_t chunkSize) {
            ASSERT_EQ(ResultCode::OK, hidl_error);
            ASSERT_GT(credentialStoreName.size(), 0u);
            ASSERT_GT(credentialStoreAuthorName.size(), 0u);
            ASSERT_GE(chunkSize, 256u); // Chunk sizes smaller than APDU buffer won't be supported

            mMaxChunkSize = chunkSize;
        });
    }
    virtual void TearDown() override {}

    ResultCode CreateCredential(hidl_vec<uint8_t>* out_credentialBlob) {
        ResultCode error;
        hidl_vec<uint8_t> empty;

        credentialstore_->createCredential(
                "NewCredential", false,
                [&](ResultCode hidl_error, const sp<IWritableIdentityCredential>& newCredential) {
                    error = hidl_error;
                    ASSERT_NE(newCredential, nullptr);

                    newCredential->startPersonalization(
                            empty, empty, testProfiles.size(), testEntries.size(),
                            [&](ResultCode hidl_error, const hidl_vec<uint8_t>& /* certificate */,
                                const hidl_vec<uint8_t>& credentialBlob) {
                                ASSERT_EQ(ResultCode::OK, hidl_error);
                                // testCredentialBlob.resize(credentialBlob.size());
                                // std::copy(credentialBlob.begin(), credentialBlob.end(),
                                //           testCredentialBlob.begin());

                                *out_credentialBlob = credentialBlob;
                            });
                });
        return error;
    }

    uint32_t mMaxChunkSize = 0;

    sp<IIdentityCredentialStore> credentialstore_;
};

/*************************************************** 
 *                  TEST CASES                     *
 ***************************************************/
TEST_F(IdentityCredentialStoreHidlTest, HardwareConfiguration) {
    ALOGD("Test HardwareInformation");
    credentialstore_->getHardwareInformation([&](ResultCode hidl_error,
                                                 const hidl_string& credentialStoreName,
                                                 const hidl_string& credentialStoreAuthorName,
                                                 uint32_t chunkSize) {
        ASSERT_EQ(ResultCode::OK, hidl_error);
        ASSERT_GT(credentialStoreName.size(), 0u);
        ASSERT_GT(credentialStoreAuthorName.size(), 0u);
        ASSERT_GE(chunkSize, 256u);  // Chunk sizes smaller than APDU buffer won't be supported
    });
}

TEST_F(IdentityCredentialStoreHidlTest, CreateCredential) {
    ALOGD("Test CreateCredential");
    credentialstore_->createCredential(
            "NewCredential", false,
            [&](ResultCode hidl_error, const sp<IWritableIdentityCredential>& newCredential) {
                ASSERT_EQ(ResultCode::OK, hidl_error);
                ASSERT_NE(newCredential, nullptr);
            });
}


TEST_F(IdentityCredentialStoreHidlTest, ProvisionTestCredential) {
    ALOGD("Test Provisioning Credential");

    sp<IWritableIdentityCredential> writeableCredential;
    
    hidl_vec<uint8_t> empty{0};

    credentialstore_->createCredential(
        "TestCredential", true,
        [&](ResultCode hidl_error, const sp<IWritableIdentityCredential>& newCredential) {
            ASSERT_EQ(ResultCode::OK, hidl_error);
            writeableCredential = newCredential;
        });

    ASSERT_NE(writeableCredential, nullptr);

    writeableCredential->startPersonalization(
        empty, empty, testProfiles.size(), testEntries.size(),
        [&](ResultCode hidl_error, const hidl_vec<uint8_t>& certificate,
            const hidl_vec<uint8_t>& credentialBlob) {
            ASSERT_EQ(ResultCode::OK, hidl_error);
            ASSERT_EQ(180u, certificate.size());    // TODO: what is the correct certificate size?
            ASSERT_EQ(kAesGcmIvSize + kAesGcmTagSize + kAesGcmKeySize + kECKeySize
                              + 4,               // for CBOR structure in encrypted blob
                      credentialBlob.size()); 

            // TODO: check the content of credentialBlob and auditLogHash
        });

    for (const auto& testProfile : testProfiles) {
        writeableCredential->addAccessControlProfile(
            testProfile.id, testProfile.readerAuthPubKey, testProfile.capabilityId,
            testProfile.capabilityType, testProfile.timeout,
            [&](ResultCode hidl_error, SecureAccessControlProfile profile) {
                ASSERT_EQ(ResultCode::OK, hidl_error);

                ASSERT_EQ(testProfile.id, profile.id);
                ASSERT_EQ(testProfile.readerAuthPubKey, profile.readerAuthPubKey);
                ASSERT_EQ(testProfile.capabilityId, profile.capabilityId);
                ASSERT_EQ(testProfile.capabilityType, profile.capabilityType);
                ASSERT_EQ(testProfile.timeout, profile.timeout);

                ASSERT_EQ(kAesGcmTagSize + kAesGcmIvSize, profile.mac.size());
                // TODO check mac
            });
    }

    for (const auto& entry : testEntries) {
        std::vector<SecureAccessControlProfile> acProfiles;

        for(const auto & id : entry.second){
            SecureAccessControlProfile newProfile;
            newProfile.id = id;
            acProfiles.push_back(newProfile);
        }

        uint32_t entrySize = 0;
        if(entry.first.value.getDiscriminator() == EntryValue::hidl_discriminator::byteString){
            entrySize = entry.first.value.byteString().size();
        } else if(entry.first.value.getDiscriminator() == EntryValue::hidl_discriminator::textString){
            entrySize = entry.first.value.textString().size();
        }

        writeableCredential->beginAddEntry(acProfiles, entry.first.nameSpace, entry.first.name,
                                  entry.first.directlyAvailable, entrySize);

        writeableCredential->addEntryValue(entry.first.value,
                                  [&](ResultCode hidl_error, hidl_vec<uint8_t> encryptedContent) {
                                      ASSERT_EQ(ResultCode::OK, hidl_error);
                                      ASSERT_GT(encryptedContent.size(), 0u);

                                      // TODO check the encrypted data
                                  });
    }

    writeableCredential->finishAddingEntryies(
            [&](ResultCode hidl_error, hidl_vec<uint8_t> signedData) {
                ASSERT_EQ(ResultCode::OK, hidl_error);
                
                // The last entry should have the signature
                ASSERT_NE(0u, signedData.size());
            });

    writeableCredential = nullptr;
}



TEST_F(IdentityCredentialStoreHidlTest, GetCredential) {
    ALOGD("GetCredentialTest ");
    sp<IIdentityCredential> readCredential;
    hidl_vec<uint8_t> empty{0};
    hidl_vec<uint8_t> testCredentialBlob{0};

    CreateCredential(&testCredentialBlob);

    ASSERT_GT(testCredentialBlob.size(), 0u);
    credentialstore_->getCredential(
        testCredentialBlob,
        [&](ResultCode hidl_error, const sp<IIdentityCredential>& loadedCredential) {
            ASSERT_EQ(ResultCode::OK, hidl_error);
            ASSERT_NE(loadedCredential, nullptr);
            readCredential = loadedCredential;
        });
} 


TEST_F(IdentityCredentialStoreHidlTest, TestCreateEphemeralKey) {
    ALOGD("CreateEphemeralKeyTest ");
    sp<IIdentityCredential> readCredential;

    hidl_vec<uint8_t> testCredentialBlob{0};

    CreateCredential(&testCredentialBlob);

    credentialstore_->getCredential(
            testCredentialBlob,
            [&](ResultCode hidl_error, const sp<IIdentityCredential>& loadedCredential) {
                ASSERT_EQ(ResultCode::OK, hidl_error);
                ASSERT_NE(loadedCredential, nullptr);
                readCredential = loadedCredential;
            });
    ASSERT_NE(readCredential, nullptr);

    readCredential->createEphemeralKeyPair(
            KeyType::EC_NIST_P_256,
            [&](const hidl_vec<uint8_t>& ephemeralKey) { 
                ASSERT_GT(ephemeralKey.size(), 0u); 
            });
} 

}  // namespace test
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android