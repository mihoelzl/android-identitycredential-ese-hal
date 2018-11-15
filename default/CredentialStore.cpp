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

#include "CredentialStore.h"

namespace android {
namespace hardware {
namespace credential {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::credential::V1_0::ICredentialStore follow.
Return<void> CredentialStore::createCredential(const hidl_vec<uint8_t>& iaKeyCertificate, const hidl_string& credentialType, const hidl_vec<::android::hardware::credential::V1_0::AccessControlProfile>& accessControlProfiles, const hidl_vec<::android::hardware::credential::V1_0::EntryConfiguration>& entries, const hidl_vec<uint8_t>& issuerSignature, bool testCredential, createCredential_cb _hidl_cb) {
    

    ALOGD("%zu", iaKeyCertificate.size());
    ALOGD("%zu", sizeof(accessControlProfiles));
    ALOGD("%zu", entries.size());
    ALOGD("%s", credentialType.c_str());

    if(testCredential){
        ALOGD("%zu", issuerSignature.size());
    }

    // TODO implement
    _hidl_cb(ErrorCode::OK, NULL, NULL, NULL, NULL);


    return Void();
}

Return<void> CredentialStore::getCredential(const hidl_vec<uint8_t>& credentialBlob, getCredential_cb _hidl_cb) {
    
    ALOGD("%zu", credentialBlob.size());

    // TODO implement
    _hidl_cb(ErrorCode::OK, NULL);

    return Void();
}

// Methods from ::android::hidl::base::V1_0::IBase follow.

//ICredentialStore* HIDL_FETCH_ICredentialStore(const char* /* name */) {
    //return new CredentialStore();
//}
//
}  // namespace implementation
}  // namespace V1_0
}  // namespace credential
}  // namespace hardware
}  // namespace android
