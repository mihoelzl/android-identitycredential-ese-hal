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


#define LOG_TAG "android.hardware.identity_credential@1.0-impl"
#include <log/log.h>

#include "IdentityCredential.h"

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredential follow.
Return<void> IdentityCredential::deleteCredential(deleteCredential_cb _hidl_cb) {
    // TODO implement
    _hidl_cb(Error::OK, NULL);
  
    return Void();
}

Return<void> IdentityCredential::createEphemeralKeyPair(::android::hardware::identity_credential::V1_0::KeyType keyType, createEphemeralKeyPair_cb _hidl_cb) {
    // TODO implement
    _hidl_cb(NULL);

    ALOGD("%zu", sizeof(keyType));

    return Void();
}

Return<void> IdentityCredential::getEntries(const hidl_vec<hidl_vec<uint8_t>>& accessControlDescriptors, const hidl_vec<hidl_vec<uint8_t>>& entryBlobs, const ::android::hardware::keymaster::capability::V1_0::KeymasterCapability& authToken, const hidl_vec<uint8_t>& sessionTranscript, const hidl_vec<uint8_t>& readerSignature, const hidl_vec<uint8_t>& signingKeyBlob, const hidl_vec<hidl_vec<uint8_t>>& signingKeyChain, getEntries_cb _hidl_cb) {
    
    // TODO implement
    _hidl_cb(Error::OK, NULL, NULL);

    for(const auto &entry : entryBlobs){
        ALOGD("%zu", entry.size());
        ALOGD("Bladde");
    }
    ALOGD("%zu", accessControlDescriptors.size());
    ALOGD("%zu", sizeof(authToken));
    ALOGD("%zu", sizeof(signingKeyChain));
    ALOGD("%zu", sessionTranscript.size());
    ALOGD("%zu", readerSignature.size());
    ALOGD("%zu", signingKeyBlob.size());
    return Void();
}

Return<void> IdentityCredential::generateSigningKeyPair(::android::hardware::identity_credential::V1_0::KeyType keyType, generateSigningKeyPair_cb _hidl_cb) {
    
    ALOGD("%zu", sizeof(keyType));

    _hidl_cb(Error::OK, NULL, NULL);

    // TODO implement
    return Void();
}


Return<::android::hardware::identity_credential::V1_0::Error> IdentityCredential::provisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& signingKeyBlob, const hidl_vec<hidl_vec<uint8_t>>& signingKeyCertificateChain) {
    // TODO implement
    ALOGD("%zu", sizeof(signingKeyCertificateChain));
    ALOGD("%zu", signingKeyBlob.size());

    return ::android::hardware::identity_credential::V1_0::Error {};
}

Return<void> IdentityCredential::getDirectAccessSigningKeyPairCounts(getDirectAccessSigningKeyPairCounts_cb _hidl_cb) {
    // TODO implement
    _hidl_cb(Error::OK, NULL, 0);

    return Void();
}

Return<::android::hardware::identity_credential::V1_0::Error> IdentityCredential::deprovisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& signingKeyBlob) {
    // TODO implement
    ALOGD("%zu", signingKeyBlob.size());

    return ::android::hardware::identity_credential::V1_0::Error {};
}


}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
