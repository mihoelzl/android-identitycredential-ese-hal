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
#define LOG_TAG "identity_credential_hidl_test"

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
 class IdentityCredentialStoreHidlEnvironment : public VtsHalHidlTargetTestEnvBase {
    public:
        // get the test environment singleton
        static IdentityCredentialStoreHidlEnvironment* Instance() {
            static IdentityCredentialStoreHidlEnvironment* instance = new IdentityCredentialStoreHidlEnvironment;
            return instance;
        }
         virtual void registerTestServices() override { registerTestService<IIdentityCredentialStore>(); }
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
    }
    sp<IIdentityCredentialStore> credentialstore_;
};


const EntryData testEntry1 = {
    "PersonalData",
    "Last name",
    "Hoelzl",
    false
};

const EntryData testEntry2 = {
    "PersonalData",
    "First name",
    "Michael",
    false
};

const EntryData testEntry3 = {
    "PersonalData",
    "Birth date",
    "19800102",
    false
};

const uint8_t testProfile1ID = 0u;
const hidl_vec<uint8_t> testProfile1ReaderKey = {
    0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F,
    0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F};

const uint8_t testProfile2ID = 1u;
const uint64_t testProfile2CapabilityId = 0x1234567890ABCDEF;
const CapabilityType testProfile2CapabilityType = CapabilityType::ANY;
const uint64_t testProfile2Timeout = 100u;

const uint8_t nrOfEntries = 3;
const uint8_t nrOfProfiles = 2;

TEST_F(IdentityCredentialStoreHidlTest, HardwareConfiguration) {
    ALOGD("HardwareInformation available ");

    credentialstore_->getHardwareInformation([&](const hidl_string& credentialStoreName, const hidl_string& credentialStoreAuthorName, uint32_t chunkSize){
        ALOGD("Callback received");
        ASSERT_FALSE(credentialStoreName.empty());
        ASSERT_FALSE(credentialStoreAuthorName.empty());
        ALOGD("Not NULL");
        ASSERT_GT(credentialStoreName.size(), 0u);
        ASSERT_GT(credentialStoreAuthorName.size(), 0u);
        ASSERT_GE(chunkSize, 256u); // Chunk sizes smaller than APDU buffer won't be supported
    }
    );
}

TEST_F(IdentityCredentialStoreHidlTest, CreateCredential) {
    ALOGD("CreateTestCredential");
    credentialstore_->createCredential("NewCredential", false,
            [&](ResultCode hidl_error, const sp<IWritableIdentityCredential>& newCredential) {
                EXPECT_EQ(ResultCode::OK, hidl_error);
                EXPECT_NE(newCredential, nullptr);
                }
    );
}

TEST_F(IdentityCredentialStoreHidlTest, CreateTestCredential) {
    ALOGD("CreateCredential");
    sp<IWritableIdentityCredential> credential;
    hidl_vec<uint8_t> empty{0};

    credentialstore_->createCredential(
        "TestCredential", true,
        [&](ResultCode hidl_error, const sp<IWritableIdentityCredential>& newCredential) {
            ASSERT_EQ(ResultCode::OK, hidl_error);
            ASSERT_NE(newCredential, nullptr);
            credential = newCredential;
        });

    ALOGD("Credential initialized, personalizing %p", credential.get());
    credential->startPersonalization(
        empty, empty, nrOfProfiles, nrOfEntries,
        [&](ResultCode hidl_error, const hidl_vec<uint8_t>& certificate,
            const hidl_vec<uint8_t>& credentialBlob, AuditLogHash auditLogHash) {
            ALOGD("Credential personalizing done");
            ASSERT_EQ(ResultCode::OK, hidl_error);
            ASSERT_EQ(180u, certificate.size());    // TODO: what is the correct certificate size?
            ASSERT_EQ(98u, credentialBlob.size());  // 128-bit AES key + 256-bit EC key encrypted
            ASSERT_EQ(32u, auditLogHash.hashValue.size());
        });

    credential->addAccessControlProfile(
        testProfile1ID, testProfile1ReaderKey, 0u, CapabilityType::NOT_APPLICABLE, 0u,
        [&](ResultCode hidl_error, SecureAccessControlProfile profile) {
            ASSERT_EQ(ResultCode::OK, hidl_error);
            ASSERT_EQ(testProfile1ID, profile.id);
            ASSERT_EQ(testProfile1ReaderKey, profile.readerAuthPubKey);
            ASSERT_EQ(0u, profile.capabilityId);
            ASSERT_EQ(0u, profile.timeout);
            // TODO check mac
        });

    credential->addAccessControlProfile(
        testProfile2ID, hidl_vec<uint8_t>{}, testProfile2CapabilityId, testProfile2CapabilityType,
        testProfile2Timeout, [&](ResultCode hidl_error, SecureAccessControlProfile profile) {
            ASSERT_EQ(ResultCode::OK, hidl_error);
            ASSERT_EQ(testProfile2ID, profile.id);
            ASSERT_EQ(0u, profile.readerAuthPubKey.size());
            ASSERT_EQ(testProfile2CapabilityId, profile.capabilityId);
            ASSERT_EQ(testProfile2CapabilityType, profile.capabilityType);
            ASSERT_EQ(testProfile2Timeout, profile.timeout);
            // TODO check mac
        });
}

/*
hidl_vec<uint8_t> testCredentialBlob = {0,1,2};

TEST_F(IdentityCredentialStoreHidlTest, LoadCredential) {
    ALOGD("GetCredentialTest ");
    credentialstore_->getCredential(testCredentialBlob,
            [&](ResultCode hidl_error, const sp<IIdentityCredential>& credential) {
                EXPECT_EQ(ResultCode::OK, hidl_error);
                EXPECT_NE(credential, nullptr);
                }
    );
} */

}  // namespace test
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android