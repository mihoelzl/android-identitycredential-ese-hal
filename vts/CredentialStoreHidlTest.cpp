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
using ::android::hardware::keymaster::capability::V1_0::KeymasterCapability;
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

const EntryData testLargeEntry1 {
    "Image",
    "Portrait image",
    hidl_vec<uint8_t>{1,2,3,4}, // TODO: change to actual large image data
    false
};

const std::vector<std::pair<EntryData, hidl_vec<uint8_t>>> testEntries{
    {testEntry1, {1}},
    {testEntry2, {2}},
    {testEntry3, {3}},
    {testEntry4, {0, 1}},
    {testLargeEntry1, {1,3}}
};


const std::vector<uint16_t> nrOrEntriesInNamespaces = {static_cast<uint16_t>(testEntries.size() - 1),
                                                       1u};

// Test reader authentication keys
// const KeyType testReaderAuthPublicKeyType = KeyType::EC_NIST_P_256;

const hidl_vec<uint8_t> testReaderAuthPublicKey = {
        0x04, 0xD0, 0x4A, 0x6D, 0xA5, 0x47, 0x78, 0xB4, 0xA8, 0xA1, 0xBA, 0xDE, 0x53,
        0x18, 0xF2, 0x48, 0xA9, 0xFC, 0x32, 0xE6, 0xEF, 0xE8, 0x06, 0x3E, 0x36, 0x8D,
        0xF3, 0xFD, 0xC6, 0xCA, 0x2A, 0x97, 0x89, 0xCC, 0xCF, 0x38, 0x1F, 0xE4, 0xD9,
        0x70, 0x6B, 0x18, 0x08, 0xEB, 0x80, 0xE5, 0x78, 0x4C, 0x02, 0x94, 0x18, 0x04,
        0xBC, 0x6E, 0x25, 0x1B, 0x5A, 0x71, 0xC3, 0x45, 0xF4, 0xC1, 0xE7, 0xA7, 0x52};

struct TestProfile{
    uint8_t id;
    hidl_vec<uint8_t> readerAuthPubKey;
    uint64_t capabilityId;
    CapabilityType capabilityType;
    uint64_t timeout;
};

        
// Profile 1 (reader authentication)
const TestProfile testProfile1 = {0u,
                                  testReaderAuthPublicKey,
                                  0u,
                                  CapabilityType::NOT_APPLICABLE,
                                  0u};

// Profile 2 (user authentication)
const TestProfile testProfile2 = {1u, {}, 0x1234567890ABCDEF, CapabilityType::ANY, 100u};

// Profile 3 (user + reader authentication)
const TestProfile testProfile3 = {2u,
                                  testReaderAuthPublicKey,
                                  0x1234567890ABCDEF,
                                  CapabilityType::ANY,
                                  100u};

// Profile 4 (no authentication)
const TestProfile testProfile4 = {3u, {}, 0u, CapabilityType::NOT_APPLICABLE, 0u};

const std::vector<TestProfile> testProfiles {testProfile1, testProfile2, testProfile3, testProfile4};

/************************************
 *   TEST DATA FOR AUTHENTICATION
 ************************************/
// Test authentication token for user authentication
const KeymasterCapability testAuthToken {
        123456,
        {1},
        CapabilityType::ANY,
        666666,
        hidl_vec<uint8_t>{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}};

/** 
 * Test request data 
 * {
 *   "SessionTranscript": [              
 *           h'41414141414141414141414141414141',
 *           h'4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F4F'
 *   ],
 *   "Request": {
 *       "DocType": "org.iso18013.mdl",
 *       "PersonalData": [
 *           "Last name",
 *           "Birth date",
 *           "First Name",
 *           "Home Address"
 *       ],
 *       "Image": [
 *           "Portrait image"
 *       ]
 *   }
 * }
 */
const hidl_vec<uint8_t> testRequestData = {
        0xA2, 0x71, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x54, 0x72, 0x61, 0x6E, 0x73, 0x63,
        0x72, 0x69, 0x70, 0x74, 0x82, 0x50, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x58, 0x20, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
        0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
        0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x67, 0x52, 0x65, 0x71,
        0x75, 0x65, 0x73, 0x74, 0xA3, 0x67, 0x44, 0x6F, 0x63, 0x54, 0x79, 0x70, 0x65, 0x70, 0x6F,
        0x72, 0x67, 0x2E, 0x69, 0x73, 0x6F, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2E, 0x6D, 0x64, 0x6C,
        0x6C, 0x50, 0x65, 0x72, 0x73, 0x6F, 0x6E, 0x61, 0x6C, 0x44, 0x61, 0x74, 0x61, 0x84, 0x69,
        0x4C, 0x61, 0x73, 0x74, 0x20, 0x6E, 0x61, 0x6D, 0x65, 0x6A, 0x42, 0x69, 0x72, 0x74, 0x68,
        0x20, 0x64, 0x61, 0x74, 0x65, 0x6A, 0x46, 0x69, 0x72, 0x73, 0x74, 0x20, 0x4E, 0x61, 0x6D,
        0x65, 0x6C, 0x48, 0x6F, 0x6D, 0x65, 0x20, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65,
        0x49, 0x6D, 0x61, 0x67, 0x65, 0x81, 0x6E, 0x50, 0x6F, 0x72, 0x74, 0x72, 0x61, 0x69, 0x74,
        0x20, 0x69, 0x6D, 0x61, 0x67, 0x65};

// Signature using private key corresponding the reader public key of above
const hidl_vec<uint8_t> testRequestDataSignature = {
        0x30, 0x44, 0x02, 0x20, 0x0e, 0x7c, 0xf8, 0x84, 0xa8, 0x4d, 0x81, 0x6e, 0xee, 0x8e,
        0x0d, 0x54, 0x8f, 0xef, 0xb2, 0x7b, 0xd9, 0x10, 0x6e, 0xc4, 0x12, 0x6c, 0xec, 0x06,
        0x93, 0x9d, 0x7d, 0xed, 0x3c, 0xce, 0x91, 0xa6, 0x02, 0x20, 0x38, 0x53, 0x4e, 0xb2,
        0xe4, 0x6b, 0xb2, 0xde, 0xec, 0xda, 0x05, 0x3b, 0x95, 0x0c, 0xe2, 0xea, 0x1e, 0x9c,
        0xc1, 0xf2, 0xd8, 0xfa, 0x68, 0xae, 0x4e, 0x36, 0x7e, 0x03, 0x8b, 0x82, 0xd8, 0x0a};

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
    ALOGD("CreateEphemeralKeyTest");
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

TEST_F(IdentityCredentialStoreHidlTest, TestRetrieveEntries) {
    ALOGD("TestRetrieveEntires");
    sp<IIdentityCredential> readCredential;

    hidl_vec<uint8_t> testCredentialBlob{0};
    StartRetrievalArguments startArguments;

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
    
    std::vector<SecureAccessControlProfile> secureTestProfiles;
    
    // Specify secure access control profile
    for(auto& profile : testProfiles){
        SecureAccessControlProfile sProfile;
        sProfile.id = profile.id;
        sProfile.readerAuthPubKey = profile.readerAuthPubKey;
        sProfile.capabilityId = profile.capabilityId;
        sProfile.capabilityType = profile.capabilityType;
        sProfile.timeout = profile.timeout;
        // TODO(hoelzl) dynamically compute mac with test credential keys
        sProfile.mac = hidl_vec<uint8_t>{0,2,3,4,5};

        secureTestProfiles.push_back(sProfile);
    }
    startArguments.accessControlProfiles = secureTestProfiles;

    // User authentication token
    startArguments.authToken = testAuthToken;

    // Two namespaces
    startArguments.requestCounts = nrOrEntriesInNamespaces;

    // Test request
    startArguments.requestData = testRequestData;

    startArguments.readerSignature = testRequestDataSignature;
    
    readCredential->startRetrieval(startArguments,
                                   [&](ResultCode hidl_error, const hidl_vec<uint8_t> failedIds) {
                                       ASSERT_EQ(ResultCode::OK, hidl_error);
                                       ASSERT_NE(failedIds.size(), 0u);
                                   });
}

}  // namespace test
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android