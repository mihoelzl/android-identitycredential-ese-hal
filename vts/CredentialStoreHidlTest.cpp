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
    ALOGD("CreateCredential");
    sp<IWritableIdentityCredential> credential;
    hidl_vec<uint8_t> empty{0};

    credentialstore_->createCredential("TestCredential", false,
            [&](ResultCode hidl_error, const sp<IWritableIdentityCredential>& newCredential) {
                ASSERT_EQ(ResultCode::OK, hidl_error);
                ASSERT_NE(newCredential, nullptr);
                credential = newCredential;
            });

    ALOGD("Credential initialized, personalizing %p", credential.get());
    credential->startPersonalization(
        empty, empty, 2, 4,
        [&](ResultCode hidl_error, const hidl_vec<uint8_t>& certificate,
            const hidl_vec<uint8_t>& credentialBlob, AuditLogHash auditLogHash) {
                ALOGD("Credential personalizing done");
                ASSERT_EQ(ResultCode::OK, hidl_error);
                ASSERT_EQ(180u, certificate.size()); // TODO: what is the correct certificate size?
                ASSERT_EQ(98u, credentialBlob.size()); // 128-bit AES key + 256-bit EC key encrypted
                ASSERT_EQ(32u, auditLogHash.hashValue.size());
        });
    
}
/*
TEST_F(IdentityCredentialStoreHidlTest, CreateTestCredential) {
    ALOGD("CreateTestCredential");
    credentialstore_->createCredential("TestCredential", true,
            [&](ResultCode hidl_error, const sp<IWritableIdentityCredential>& newCredential) {
                EXPECT_EQ(ResultCode::OK, hidl_error);
                EXPECT_NE(newCredential, nullptr);
                }
    );
}

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