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


namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

static constexpr uint8_t kINSLoadCredential = 0x50;

template<typename iter_t>
std::string bytes_to_hex(iter_t begin, iter_t const& end)
{
    std::ostringstream hex;
    hex << std::hex;
    while (begin != end)
        hex << static_cast<unsigned>(*begin++);
    return hex.str();
}

Error IdentityCredential::initializeCredential(const hidl_vec<uint8_t>& credentialBlob){

    if (!mAppletConnection.connectToSEService()) {
        ALOGE("Error while trying to connect to SE service");
        return Error::IOERROR;
    }

    Error st = mAppletConnection.openChannelToApplet();
    if(st != Error::OK){
        return st;
    }

    // Send the command to the applet to load the applet
    CommandApdu command{0x80, kINSLoadCredential, 0, 0, credentialBlob.size(), 0};
    std::copy(credentialBlob.begin(), credentialBlob.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if(!response.ok()){
        return Error::IOERROR;
    } else if(response.isError()){
        return Error::FAILED;
    }

    if(response.status() == 0x9000){
        return Error::OK;
    }

    return Error::FAILED;
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

Return<void> IdentityCredential::getEntries(
    const hidl_vec<hidl_vec<uint8_t>>& /*accessControlDescriptors*/,
    const hidl_vec<hidl_vec<uint8_t>>& /*entryBlobs*/,
    const ::android::hardware::keymaster::capability::V1_0::KeymasterCapability& /*authToken*/,
    const hidl_vec<uint8_t>& /*sessionTranscript*/, const hidl_vec<uint8_t>& /*readerSignature*/,
    const hidl_vec<uint8_t>& /*signingKeyBlob*/, const hidl_vec<hidl_vec<uint8_t>>& /*signingKeyChain*/,
    getEntries_cb /*_hidl_cb*/) {
    // TODO implement

    return Void();
}

Return<void> IdentityCredential::generateSigningKeyPair(
    ::android::hardware::identity_credential::V1_0::KeyType /*keyType*/,
    generateSigningKeyPair_cb /*_hidl_cb*/) {
    
    // TODO implement
    return Void();
}

Return<Error>
IdentityCredential::provisionDirectAccessSigningKeyPair(
    const hidl_vec<uint8_t>& /*signingKeyBlob*/,
    const hidl_vec<hidl_vec<uint8_t>>& /*signingKeyCertificateChain*/) {
    // TODO implement

    return Error::OK;
}

Return<void> IdentityCredential::getDirectAccessSigningKeyPairCounts(
    getDirectAccessSigningKeyPairCounts_cb /*_hidl_cb*/) {
    // TODO implement

    return Void();
}

Return<::android::hardware::identity_credential::V1_0::Error>
IdentityCredential::deprovisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& /*signingKeyBlob*/) {
    // TODO implement

    return ::android::hardware::identity_credential::V1_0::Error{};
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
