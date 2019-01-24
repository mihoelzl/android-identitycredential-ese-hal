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
#include "IdentityCredentialStore.h"

#include <cmath>
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
const uint8_t kMaxCBORHeader = 5;
const uint8_t kMaxApduHeader = 13; // Extended length

sp<SecureElementCallback> mCallback;

bool AppletConnection::connectToSEService() {
    if (mSEClient != nullptr && mCallback->isClientConnected()) {
        ALOGD("Already connected");
        return true;
    }

    mSEClient = ISecureElement::getService("eSE1");

    if (mSEClient != nullptr) {
        if (mCallback == nullptr) {
            mCallback = new SecureElementCallback();
        }
        mSEClient->init(mCallback);
        return true;
    }
    return false;
}

ResponseApdu AppletConnection::openChannelToApplet(){
    if (isChannelOpen()) {
        close();
    }
    if(mSEClient == nullptr || !mCallback->isClientConnected()){ // Not connected to SE service
        return ResponseApdu({});
    }

    std::vector<uint8_t> resp;
    mSEClient->openLogicalChannel(
        kAndroidIdentityCredentialAID, 00,
        [&](LogicalChannelResponse selectResponse, SecureElementStatus status) {
            if (status == SecureElementStatus::SUCCESS) {
                resp = selectResponse.selectResponse;
                // APDU buffer size is encoded in select response
                mApduMaxBufferSize = (*resp.begin() << 8) + *(resp.begin() + 1) - kMaxApduHeader;

                // Chunck size is encoded in select response
                mAppletChunkSize = (*(resp.begin()+2) << 8) + *(resp.begin() + 3);

                // Actual maximum data chunk size needs to take cbor header in account
                mHalChunkSize = mAppletChunkSize - kMaxCBORHeader;

                mOpenChannel = selectResponse.channelNumber;
            }
        });
    return ResponseApdu(resp);
}

const ResponseApdu AppletConnection::transmit(CommandApdu& command, bool decryption){
    if(!isChannelOpen() || mSEClient == nullptr){
        return ResponseApdu(std::vector<uint8_t>{0});
    }
    
    bool getResponseEmpty = false;
    std::vector<uint8_t> fullResponse;
    uint16_t nrOfAPDUchains = 1;
 
    // Configure the logical channel
    *command.begin() |= mOpenChannel;

    size_t encryptionOverhead = decryption ? IdentityCredentialStore::ENCRYPTION_OVERHEAD : 0;

    if(command.dataSize() > mAppletChunkSize + encryptionOverhead){
        ALOGE("Data too big (%zu/%hu), abort", command.dataSize(), mAppletChunkSize);
        return ResponseApdu({});
    } else if (command.size() > mApduMaxBufferSize){
        // Too big for APDU buffer, perform APDU chaining
        nrOfAPDUchains = std::ceil(static_cast<float>(command.dataSize()) / mApduMaxBufferSize);        
        ALOGD("Too big for APDU buffer. Sending %hu chains", nrOfAPDUchains);
    }
    
    std::vector<uint8_t> cmdVec = command.vector();
        
    for (uint8_t i = 0; i < nrOfAPDUchains; i++) {
        size_t apduSize = 0;
        if (((i + 1) * mApduMaxBufferSize) <= command.dataSize()) {
            apduSize = mApduMaxBufferSize;
        } else {
            apduSize = command.dataSize() - i * mApduMaxBufferSize;
        }

        CommandApdu subCommand(cmdVec[0], cmdVec[1], cmdVec[2], cmdVec[3], apduSize, 0);

        auto first = command.dataBegin() + (i * mApduMaxBufferSize);
        auto last = first + apduSize;
        std::copy(first, last, subCommand.dataBegin());

        if (i != nrOfAPDUchains - 1) {
            *subCommand.begin() |= 0x10; // APDU chain
        } 

        mSEClient->transmit(subCommand.vector(), [&](hidl_vec<uint8_t> responseData) {
            ALOGD("Data received: %zu", responseData.size());
            fullResponse = responseData;
        });
    }

    // Check if more data is available 
    while (fullResponse.size() >= 2 && (*(fullResponse.end() - 2) == 0x61) && !getResponseEmpty) {
        uint8_t le = *(fullResponse.end() - 1);
        CommandApdu getResponse = CommandApdu(mOpenChannel, kINSGetRespone, 0, 0, 0, le == 0 ? 256 : le);

        mSEClient->transmit(getResponse.vector(), [&](hidl_vec<uint8_t> responseData) {
            if (responseData.size() < 2) {
                *(fullResponse.end() - 2) = 0x67;  // Wrong length
                *(fullResponse.end() - 1) = 0x00;
            } else {
                // Copy additional data to response buffer
                fullResponse.resize(fullResponse.size() + responseData.size() - 2);

                std::copy(responseData.begin(), responseData.end(), fullResponse.end() - responseData.size());
                
                if (responseData.size() == 2){
                    getResponseEmpty = true;
                }
            }
        });
    }

    return ResponseApdu(fullResponse);
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
