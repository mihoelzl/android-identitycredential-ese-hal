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

#define LOG_TAG "android.hardware.credential@1.0-impl"
#include <log/log.h>


#include <android/hardware/credential/1.0/ICredentialStore.h>
#include <android/hardware/credential/1.0/types.h>

#include <VtsHalHidlTargetTestBase.h>
#include <VtsHalHidlTargetTestEnvBase.h>

using ::testing::VtsHalHidlTargetTestEnvBase;

namespace android {
namespace hardware {
namespace credential {
namespace V1_0 {
namespace test {


class CredentialStoreHidlEnvironment : public VtsHalHidlTargetTestEnvBase {
    public:
        // get the test environment singleton
        static CredentialStoreHidlEnvironment* Instance() {
            static CredentialStoreHidlEnvironment* instance = new CredentialStoreHidlEnvironment;
            return instance;
        }

        virtual void registerTestServices() override { registerTestService<ICredentialStore>(); }

    private:
        CredentialStoreHidlEnvironment() {}
};

// The main test class credential HIDL HAL.
class CredentialStoreHidlTest : public ::testing::VtsHalHidlTargetTestBase {
 public:
    virtual void SetUp() override {
        credentialstore_ =     
            ::testing::VtsHalHidlTargetTestBase::getService<ICredentialStore>(CredentialStoreHidlEnvironment::Instance()->getServiceName<ICredentialStore>());
        ASSERT_NE(credentialstore_, nullptr);
        
    }

    ErrorCode CreateCredential(const hidl_vec<uint8_t>& iaKeyCert, const string& credentialType, 
                const hidl_vec<AccessControlProfile>& accessProfiles, const hidl_vec<EntryConfiguration>& entries, 
                const hidl_vec<uint8_t> issuerSignature, hidl_vec<uint8_t>* out_credentialBlob, 
                hidl_vec<SecureAccessControlProfile>* out_secureAccessProfiles, hidl_vec<SecureEntry>* out_entries, hidl_vec<uint8_t>* out_credAttestation) {
        SCOPED_TRACE("CreateCredential");
        
        ErrorCode error;
        EXPECT_TRUE(credentialstore_->createCredential(
                            iaKeyCert, credentialType, accessProfiles, entries, issuerSignature,
                            true, //TODO: do we also want to test non-test-credentials?
                                 [&](ErrorCode hidl_error,  const hidl_vec<uint8_t>& credentialBlob,  const hidl_vec<SecureAccessControlProfile>& accessControlProfile,  const hidl_vec<SecureEntry>& en, const hidl_vec<uint8_t>& credentialAttestation) {
                                     error = hidl_error;
                                     *out_credentialBlob = credentialBlob;
                                     *out_secureAccessProfiles = accessControlProfile;
                                     *out_entries = en;
                                     *out_credAttestation = credentialAttestation;
                                 })
                        .isOk());
        return error;
    }

    ErrorCode GetCredential(const hidl_vec<uint8_t>& credentialBlob,  sp<ICredential>* out_credential) {
        SCOPED_TRACE("GetCredential");
        
        ErrorCode error;
        
        EXPECT_TRUE(credentialstore_->getCredential(
                            credentialBlob,
                                 [&](ErrorCode hidl_error, const sp<ICredential>& credential) {
                                    error = hidl_error;
                                    *out_credential = credential;
                                 })
                        .isOk());
        return error;
    }
    sp<ICredentialStore> credentialstore_;
};


}  // namespace test
}  // namespace V4_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android
