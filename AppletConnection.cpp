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

class SecureElementCallback : public ISecureElementHalCallback {
 public:
    Return<void> onStateChange(bool state) override {
        mSEClientState = state;
        return Void();
    };
    bool isClientConnected() { 
        return mSEClientState;
    }
 private:
    bool mSEClientState = false;
 
};

const std::vector<uint8_t> kAndroidIdentityCredentialAID = {0xF0, 0x49, 0x64, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x61, 0x6C, 0x00, 0x01};
const uint8_t kINSGetRespone = 0xc0;

sp<SecureElementCallback> mCallback;

bool AppletConnection::connectToSEService() {
    ALOGD("Trying to  connect to SE service");
    mSEClient = ISecureElement::getService("eSE1");

    if (mSEClient != nullptr) {
        if (mCallback == nullptr) {
            mCallback = new SecureElementCallback();
        }
        mSEClient->init(mCallback);
        ALOGD("Success!");
        return true;
    }
    return false;
}

ResponseApdu AppletConnection::openChannelToApplet(){
    if (isChannelOpen()) {
        close();
    }
    if(!mCallback->isClientConnected() || mSEClient == nullptr){ // Not connected to SE service
        return ResponseApdu({});
    }

    ALOGD("Trying to select Applet");
    std::vector<uint8_t> resp;
    mSEClient->openLogicalChannel(
        kAndroidIdentityCredentialAID, 00,
        [&](LogicalChannelResponse selectResponse, SecureElementStatus status) {
            if (status == SecureElementStatus::SUCCESS) {
                resp = selectResponse.selectResponse;
                // APDU buffer size is encoded in select response
                mApduSize = (*resp.begin() << 8) + *(resp.begin() + 1);
                // Chunck size is encoded in select response
                mChunkSize = (*(resp.begin()+2) << 8) + *(resp.begin() + 3);

                mOpenChannel = selectResponse.channelNumber;
            }
        });
    ALOGD("Successfully  selected Applet");
    return ResponseApdu(resp);
}

const ResponseApdu AppletConnection::transmit(CommandApdu& command){
    if(!isChannelOpen() || mSEClient == nullptr){
        return ResponseApdu(std::vector<uint8_t>{0});
    }
    
    bool getResponseEmpty = false;
    std::vector<uint8_t> resp;
    
    // Configure the logical channel
    *command.begin() |= mOpenChannel;

    ALOGD("Sending data %zu", command.size());

    mSEClient->transmit(command.vector(), [&](hidl_vec<uint8_t> responseData){
        ALOGD("Data received: %zu", responseData.size());
        resp = responseData;
    });

    // Check if more data is available 
    while (resp.size() >= 2 && (*(resp.end() - 2) == 0x61) && !getResponseEmpty) { 
        uint8_t le = *(resp.end()-1);
        CommandApdu getResponse = CommandApdu(mOpenChannel, kINSGetRespone, 0, 0, 0, le == 0 ? 256 : le);
        mSEClient->transmit(getResponse.vector(), [&](hidl_vec<uint8_t> responseData) {
            if (responseData.size() < 2) {
                *(resp.end()-2) = 0x67; // Wrong length
                *(resp.end()-1) = 0x00;
            } else {
                resp.resize(resp.size() + responseData.size() - 2);
                std::copy(responseData.begin(), responseData.end(), resp.end() - 2);
                if (responseData.size() == 2){
                    getResponseEmpty = true;
                }
            }
        });
    }

    return ResponseApdu(resp);
}

ResultCode AppletConnection::close() {
    if (!isChannelOpen() || mSEClient == nullptr) {
        return ResultCode::FAILED;
    }

    SecureElementStatus status = mSEClient->closeChannel(mOpenChannel);
    if (status != SecureElementStatus::SUCCESS) {
        return ResultCode::FAILED;
    }
    ALOGD("Channel closed");
    mOpenChannel = -1;
    return ResultCode::OK;
}

bool AppletConnection::isChannelOpen() {
    return mOpenChannel >= 0;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
