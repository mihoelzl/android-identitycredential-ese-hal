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
#include <android-base/logging.h>

#include <android/hardware/secure_element/1.0/ISecureElement.h>
#include <android/hardware/secure_element/1.0/ISecureElementHalCallback.h>
#include <android/hardware/secure_element/1.0/types.h>

#include "IdentityCredentialStore.h"

using android::hardware::secure_element::V1_0::ISecureElement;

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {
/*
IdentityCredentialStore::IdentityCredentialStore(){
    ALOGD("Test");
}

IdentityCredentialStore::~IdentityCredentialStore(){
    ALOGD("Test");
}*/

// Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredentialStore follow.
Return<void> IdentityCredentialStore::createCredential(const hidl_string& credentialType, bool testCredential, createCredential_cb _hidl_cb) {

    sp<ISecureElement> client = ISecureElement::getService();
    client->init(this);
    bool present = client->isCardPresent();

    if(testCredential && present){
        ALOGD("%s %d", credentialType.c_str(), present);
    }

    // TODO implement
    _hidl_cb(Error::OK, NULL);

    // TODO implement
    return Void();
}

Return<void> IdentityCredentialStore::getCredential(const hidl_vec<uint8_t>& credentialBlob, getCredential_cb _hidl_cb) {
    
    ALOGD("%zu", credentialBlob.size());

    // TODO implement
    _hidl_cb(Error::OK, NULL);

    return Void();
}

Return<void> IdentityCredentialStore::onStateChange(bool state){
    if(state){

    }
    return Void();
}

IIdentityCredentialStore* HIDL_FETCH_IIdentityCredentialStore(const char* /* name */) {
    return new IdentityCredentialStore();
}


}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
