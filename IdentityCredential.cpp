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
#include "APDU.h"
#include "CborLiteCodec.h"
#include "ICUtils.h"


namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

static constexpr uint8_t kINSLoadCredential = 0x50;

ResultCode IdentityCredential::initializeCredential(const hidl_vec<uint8_t>& credentialBlob){

    if (!mAppletConnection.connectToSEService()) {
        ALOGE("Error while trying to connect to SE service");
        return ResultCode::IOERROR;
    }

    ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
    if(selectResponse.status() != 0x9000){
        return ResultCode::FAILED;
    }

    std::string mapkey;
    unsigned long mapSize = 0;
    auto pos = std::begin(credentialBlob);
    auto len = CborLite::decodeMapSize(pos,std::end(credentialBlob), mapSize);
    if (len != 1) {
        return ResultCode::INVALID_DATA;
    }
    pos+=len;
    len = CborLite::decodeText(pos,std::end(credentialBlob), mapkey);

    if(mapkey != "credentialData"){
        return ResultCode::INVALID_DATA;
    }
    
    // Send the command to the applet to load the applet
    CommandApdu command{0x80, kINSLoadCredential, 0, 0, credentialBlob.size(), 0};
    std::copy(credentialBlob.begin(), credentialBlob.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if(!response.ok()){
        return ResultCode::IOERROR;
    } else if(response.isError()){
        return ResultCode::FAILED;
    }

    if(response.status() == 0x9000){
        return ResultCode::OK;
    }

    return ResultCode::FAILED;
}

Return<void> IdentityCredential::deleteCredential(deleteCredential_cb /*_hidl_cb*/) {
    // TODO implement

    return Void();
}

Return<void> IdentityCredential::createEphemeralKeyPair(
    ::android::hardware::identity_credential::V1_0::KeyType /*keyType*/,
    createEphemeralKeyPair_cb /*_hidl_cb*/) {
    // TODO implement

    return Void();
}
Return<void> IdentityCredential::startRetrieval(const StartRetrievalArguments& /* args */, startRetrieval_cb /* _hidl_cb */){

    return Void();
}

Return<void> IdentityCredential::retrieveEntry(const SecureEntry& /* secureEntry */,
                                                   retrieveEntry_cb /* _hidl_cb */) {
    // TODO implement

    return Void();
}

Return<void> IdentityCredential::finishRetrieval(const ::android::hardware::hidl_vec<uint8_t>& /* signingKeyBlob */, finishRetrieval_cb /* _hidl_cb */) {
    
    return Void();
}

Return<void> IdentityCredential::generateSigningKeyPair(
    ::android::hardware::identity_credential::V1_0::KeyType /*keyType*/,
    generateSigningKeyPair_cb /*_hidl_cb*/) {
    
    // TODO implement
    return Void();
}

Return<ResultCode>
IdentityCredential::provisionDirectAccessSigningKeyPair(
    const hidl_vec<uint8_t>& /*signingKeyBlob*/,
    const hidl_vec<hidl_vec<uint8_t>>& /*signingKeyCertificateChain*/) {
    // TODO implement

    return ResultCode::OK;
}

Return<void> IdentityCredential::getDirectAccessSigningKeyPairStatus(
    getDirectAccessSigningKeyPairStatus_cb /*_hidl_cb*/) {
    // TODO implement

    return Void();
}

Return<ResultCode>
IdentityCredential::deprovisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& /*signingKeyBlob*/) {
    // TODO implement

    return ResultCode::OK;
}

Return<ResultCode> IdentityCredential::configureDirectAccessPermissions(
    const hidl_vec<hidl_string>& /* itemsAllowedForDirectAccess */) {
        
    return ResultCode::OK;
}


}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
