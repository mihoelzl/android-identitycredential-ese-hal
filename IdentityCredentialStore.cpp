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

#define CREDENTIAL_STORE_NAME "ICApplet"
#define CREDENTIAL_STORE_AUTHOR_NAME "TestAuthor"

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {


Return<void> IdentityCredentialStore::getHardwareInformation(getHardwareInformation_cb _hidl_cb ) {
    AppletConnection seConnection;
    if (seConnection.connectToSEService()) {
        ResponseApdu selectResponse = seConnection.openChannelToApplet();

        if(selectResponse.ok() && selectResponse.status() == AppletConnection::SW_OK){
            ALOGD("Applet selected successfully");
            // Select response is encoded as [ APDU Buffer size || ChunkSize ]
            uint32_t chunkSize =
                (*(selectResponse.dataBegin() + 2) << 8) + *(selectResponse.dataBegin() + 3);

            _hidl_cb(CREDENTIAL_STORE_NAME, CREDENTIAL_STORE_AUTHOR_NAME, chunkSize);
            seConnection.close();
            return Void();
        } 

        ALOGD("Error selecting the applet");
        seConnection.close();
        _hidl_cb(nullptr, nullptr, 0);
        return Void();
    }
    ALOGD("Error connecting to SE service");
        
    _hidl_cb(nullptr, nullptr, 0);
    return Void();
}

// Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredentialStore follow.
Return<void> IdentityCredentialStore::createCredential(const hidl_string& credentialType,
                                                       bool testCredential,
                                                       createCredential_cb _hidl_cb) {

    if(mWritableCredentialService == nullptr){
        mWritableCredentialService = new WritableIdentityCredential();
    }

    ResultCode status = mWritableCredentialService->initializeCredential(credentialType, testCredential);

    ALOGD("Cred initialized, %d", status);
    if(status == ResultCode::OK){
        _hidl_cb(status, mWritableCredentialService);
    } else {
        _hidl_cb(status, nullptr); 
    }
    return Void();
}

Return<void> IdentityCredentialStore::getCredential(const hidl_vec<uint8_t>& credentialBlob,
                                                    getCredential_cb _hidl_cb) {
   
    if(mIdentityCredentialService == nullptr){
        mIdentityCredentialService = new IdentityCredential();
    }

    ResultCode status = mIdentityCredentialService->initializeCredential(credentialBlob);
   
    if(status == ResultCode::OK){
        _hidl_cb(status, mIdentityCredentialService);
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
