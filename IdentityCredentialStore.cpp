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

#include "IdentityCredential.h"
#include "IdentityCredentialStore.h"
#include "WritableIdentityCredential.h"


#include <android/hardware/secure_element/1.0/ISecureElement.h>
#include <android/hardware/secure_element/1.0/ISecureElementHalCallback.h>
#include <android/hardware/secure_element/1.0/types.h>


using ::android::hardware::secure_element::V1_0::ISecureElement;
using ::android::hardware::identity_credential::V1_0::implementation::WritableIdentityCredential;
using ::android::hardware::identity_credential::V1_0::implementation::IdentityCredential;


namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

const std::vector<uint8_t> IdentityCredentialStore::kAndroidIdentityCredentialAID = {0xF0, 0x49, 0x43, 0x41, 0x70, 0x70, 0x6C, 0x65, 0x74};

IdentityCredentialStore::IdentityCredentialStore() {
    connectToSEService();
}

void IdentityCredentialStore::connectToSEService(){
    mSEClient = ISecureElement::getService("eSE1");
    
    mSEClient->linkToDeath(this, 0u /* cookie */);
    mSEClient->init(this);
}

// Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredentialStore follow.
Return<void> IdentityCredentialStore::createCredential(const hidl_string& credentialType,
                                                       bool testCredential,
                                                       createCredential_cb _hidl_cb) {
    if (mSEClient == nullptr || !mSEClientState) {
        _hidl_cb(Error::OK, {}); // Error
        return Void();
    }
    
    WritableIdentityCredential *newCredential = new WritableIdentityCredential(mSEClient);

    Error status = newCredential->initializeCredential(credentialType, testCredential);

    if(status == Error::OK){
        _hidl_cb(status, newCredential);
    } else {
        delete newCredential;
        _hidl_cb(Error::OK, {}); // Error
    }

    return Void();
}

Return<void> IdentityCredentialStore::getCredential(const hidl_vec<uint8_t>& credentialBlob,
                                                    getCredential_cb _hidl_cb) {
    if (mSEClient == nullptr || !mSEClientState) {
        _hidl_cb(Error::OK, {});
        return Void();
    }
    
    IdentityCredential *loadedCredential = new IdentityCredential(mSEClient);

    Error status = loadedCredential->initializeCredential(credentialBlob);

    if(status == Error::OK){
        _hidl_cb(status, loadedCredential);
    } else {
        delete loadedCredential;
        _hidl_cb(Error::OK, {}); // Error
    }
    
    return Void();
}

Return<void> IdentityCredentialStore::onStateChange(bool state) {
    mSEClientState = state;
    return Void();
}

void IdentityCredentialStore::serviceDied(uint64_t cookie, const android::wp<::android::hidl::base::V1_0::IBase>& who){
    
    if (mSEClient != nullptr) {
        mSEClient->unlinkToDeath(this);
    }

    mSEClientState = false;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
