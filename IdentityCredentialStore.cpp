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

#define CREDENTIAL_STORE_NAME "Android IdentityCredential Applet"
#define CREDENTIAL_STORE_AUTHOR_NAME "Google Inc."

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

Return<void> IdentityCredentialStore::getHardwareInformation(getHardwareInformation_cb _hidl_cb ) {
    AppletConnection seConnection;
    if (!seConnection.connectToSEService()) {
        ALOGD("Error connecting to SE service");
            
        _hidl_cb(ResultCode::IOERROR, nullptr, nullptr, 0);
        return Void();
    }

    ResponseApdu selectResponse = seConnection.openChannelToApplet();
    if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
        ALOGD("Error selecting the applet");
        seConnection.close();
        _hidl_cb(ResultCode::IOERROR, nullptr, nullptr, 0);
        return Void();
    }

    _hidl_cb(ResultCode::OK, CREDENTIAL_STORE_NAME, CREDENTIAL_STORE_AUTHOR_NAME,
             seConnection.chunkSize());
             
    seConnection.close();

    return Void();
}

// Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredentialStore follow.
Return<void> IdentityCredentialStore::createCredential(const hidl_string& docType,
                                                       bool testCredential,
                                                       createCredential_cb _hidl_cb) {
    sp<WritableIdentityCredential> newCredential = new WritableIdentityCredential();

    ResultCode status = newCredential->initializeCredential(docType, testCredential);

    if (status == ResultCode::OK) {
        _hidl_cb(status, newCredential);
    } else {
        _hidl_cb(status, nullptr);
    }
    return Void();
}

Return<void> IdentityCredentialStore::getCredential(const hidl_vec<uint8_t>& credentialData,
                                                    getCredential_cb _hidl_cb) {
   
    sp<IdentityCredential> newCredential = new IdentityCredential();
    
    ResultCode status = newCredential->initializeCredential(credentialData);

    if (status == ResultCode::OK) {
        _hidl_cb(status, newCredential);
    } else {
        _hidl_cb(status, {});
    }
    
    return Void();
}


}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
