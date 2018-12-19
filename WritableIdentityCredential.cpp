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

#define LOG_TAG "android.hardware.identity_credential@1.0-service"
#include <log/log.h>

#include "WritableIdentityCredential.h"
#include "IdentityCredentialStore.h"


using ::android::hardware::secure_element::V1_0::SecureElementStatus;
using ::android::hardware::secure_element::V1_0::LogicalChannelResponse;


namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

static constexpr uint8_t kINSCreateCredential = 0x10;
static constexpr uint8_t kINSGetAttestationCertificate = 0x11;
static constexpr uint8_t kINSPersonalizeAccessControl = 0x12;
static constexpr uint8_t kINSPersonalizeAttribute = 0x13;
static constexpr uint8_t kINSSignPersonalizedData = 0x14;

Error WritableIdentityCredential::initializeCredential(const hidl_string& credentialType,
                                                       bool testCredential) {
    int channel;
    SecureElementStatus statusReturned;
    std::vector<uint8_t> response;
    hidl_vec<uint8_t> data;

    mSEClient->openLogicalChannel(
        IdentityCredentialStore::kAndroidIdentityCredentialAID, 00,
        [&](LogicalChannelResponse selectResponse, SecureElementStatus status) {
            statusReturned = status;
            if (status == SecureElementStatus::SUCCESS) {
                channel = selectResponse.channelNumber;
                response.resize(selectResponse.selectResponse.size());
                for (size_t i = 0; i < selectResponse.selectResponse.size(); i++) {
                    response[i] = selectResponse.selectResponse[i];
                }
            }
        });

    mSEClient->transmit(data, [&](hidl_vec<uint8_t> response) {
        response.resize(response.size());
        for (size_t i = 0; i < response.size(); i++) {
            response[i] = response[i];
        }
    });

    mSEClient->closeChannel(channel);

    return Error::OK;
}

Return<void> WritableIdentityCredential::getAttestationCertificate(
    const hidl_vec<uint8_t>& attestationApplicationId,
    const hidl_vec<uint8_t>& attestationChallenge, getAttestationCertificate_cb _hidl_cb) {

    ALOGD("%zu", attestationApplicationId.size());
    ALOGD("%zu", attestationChallenge.size());

    _hidl_cb(NULL);

    // TODO implement
    return Void();
}

Return<void> WritableIdentityCredential::personalize(
    const hidl_vec<::android::hardware::identity_credential::V1_0::AccessControlProfile>&
        accessControlProfiles,
    const hidl_vec<::android::hardware::identity_credential::V1_0::EntryConfiguration>& entries,
    personalize_cb _hidl_cb) {
        
    ALOGD("%zu", sizeof(accessControlProfiles));
    ALOGD("%zu", entries.size());

    _hidl_cb(Error::OK, NULL, NULL, NULL, NULL);

    // TODO implement
    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
