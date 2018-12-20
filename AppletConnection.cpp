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

#include "AppletConnection.h"
#include "APDU.h"

#include <functional>

using ::android::hardware::secure_element::V1_0::SecureElementStatus;
using ::android::hardware::secure_element::V1_0::LogicalChannelResponse;

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

const std::vector<uint8_t> kAndroidIdentityCredentialAID = {0xF0, 0x49, 0x64, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x61, 0x6C, 0x00, 0x01};

bool AppletConnection::connectToSEService(){
    ALOGD("Trying to  connect to SE service");
    mSEClient = ISecureElement::getService("eSE1");
    
    if (mSEClient != nullptr) {
        ALOGD("Success!");
    //    mSEClient->linkToDeath(this, 0u /* cookie */);
        mSEClient->init(this);
        return true;
    }
    return false;
}

Error AppletConnection::openChannelToApplet(){
    Error statusReturned = Error::FAILED;
    mSEClient->openLogicalChannel(
        kAndroidIdentityCredentialAID, 00,
        [&](LogicalChannelResponse selectResponse, SecureElementStatus status) {
            if (status == SecureElementStatus::SUCCESS) {
                ResponseApdu<hidl_vec<uint8_t>> res(selectResponse.selectResponse);
                if(res.ok() && res.status() == 0x9000) {
                    statusReturned = Error::OK;
                    mOpenChannel = selectResponse.channelNumber;
                } else {
                    statusReturned = Error::IOERROR;
                }
            }
        });
    return statusReturned;
}

const ResponseApdu<hidl_vec<uint8_t>> AppletConnection::transmit(const CommandApdu& command){
    if(!mSEClientState || mOpenChannel < 0){
        return ResponseApdu<hidl_vec<uint8_t>>(hidl_vec<uint8_t>{0});
    }
    hidl_vec<uint8_t> resp;
    mSEClient->transmit(command.vector(), [&](hidl_vec<uint8_t> responseData){
        ALOGD("Data received: %zu", responseData.size());
        resp = responseData;
    });
    return ResponseApdu<hidl_vec<uint8_t>>(resp);
}


Error AppletConnection::close(){
    if(!mSEClientState || mOpenChannel < 0){
        return Error::FAILED;
    }

    SecureElementStatus status = mSEClient->closeChannel(mOpenChannel);
    if(status!= SecureElementStatus::SUCCESS){
        return Error::FAILED;
    }
    return Error::OK;
}


Return<void> AppletConnection::onStateChange(bool state) {
        ALOGD("Connected to service %d", state);
    mSEClientState = state;
    return Void();
}

void AppletConnection::serviceDied(uint64_t /*cookie*/, const android::wp<::android::hidl::base::V1_0::IBase>& /*who*/){
    ALOGE("%s: SecureElement serviceDied!!!", __func__);

    if (mSEClient != nullptr) {
        mSEClient->closeChannel(0);
        mSEClient->unlinkToDeath(this);
    }

    connectToSEService();
    mSEClientState = false;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
