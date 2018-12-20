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

#include "WritableIdentityCredential.h"
#include "IdentityCredentialStore.h"


using ::android::hardware::secure_element::V1_0::SecureElementStatus;
using ::android::hardware::secure_element::V1_0::LogicalChannelResponse;


namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

static constexpr uint8_t kINSCreateCredential = 0x10;
//static constexpr uint8_t kINSGetAttestationCertificate = 0x11;
//static constexpr uint8_t kINSPersonalizeAccessControl = 0x12;
//static constexpr uint8_t kINSPersonalizeAttribute = 0x13;
//static constexpr uint8_t kINSSignPersonalizedData = 0x14;


template<typename iter_t>
std::string bytes_to_hex(iter_t begin, iter_t const& end)
{
    std::ostringstream hex;
    hex << std::hex;
    while (begin != end)
        hex << static_cast<unsigned>(*begin++);
    return hex.str();
}

WritableIdentityCredential::~WritableIdentityCredential(){
    if(mAppletConnection.isChannelOpen()){
        mAppletConnection.close();
    }
}

Error WritableIdentityCredential::initializeCredential(const hidl_string& credentialType,
                                                       bool testCredential) {

    if (!mAppletConnection.connectToSEService()) {
        ALOGD("Error when connecting");
        return Error::IOERROR;
    }

    Error st = mAppletConnection.openChannelToApplet();
    if(st != Error::OK){
        return st;
    }

    // Clear previous credentialBlob 
    mCredentialBlob.clear();

    // Send the command to the applet to create a new credential
    CommandApdu command{0x80,kINSCreateCredential,0,testCredential,credentialType.size(),0};
    std::string cred = credentialType;
    std::copy(cred.begin(), cred.end(), command.dataBegin());

    //std::vector<uint8_t> responseData 
    ResponseApdu response = mAppletConnection.transmit(command);

    if(!response.ok()){
        return Error::IOERROR;
    } else if(response.isError()){
        return Error::FAILED;
    }

    if(response.status() == 0x9000){
        ALOGD("Response: %s", bytes_to_hex(response.dataBegin(), response.dataEnd()).c_str());
        
        mCredentialBlob.assign(response.dataBegin(), response.dataEnd());
        
        return Error::OK;
    }
    return Error::INVALID_DATA;
}

Return<void> WritableIdentityCredential::getAttestationCertificate(
    const hidl_vec<uint8_t>& /*attestationApplicationId*/,
    const hidl_vec<uint8_t>& /*attestationChallenge*/, getAttestationCertificate_cb /*_hidl_cb*/) {

    // TODO implement
    
    return Void();
}

Return<void> WritableIdentityCredential::personalize(
    const hidl_vec<AccessControlProfile>& accessControlProfiles,
    const hidl_vec<EntryConfiguration>& entries, personalize_cb _hidl_cb) {
    // personalize(vec<AccessControlProfile> accessControlProfiles, vec<EntryConfiguration> entries)
    // generates(Error error, vec<uint8_t> credentialBlob,
    //                  vec<SecureAccessControlProfile> accessControlProfiles, vec<SecureEntry>
    //                  entries, vec<uint8_t> signedData);        

    ALOGD("%zu", sizeof(accessControlProfiles));
    ALOGD("%zu", entries.size());



    _hidl_cb(Error::OK, NULL, NULL, NULL, NULL);

    mAppletConnection.close();

    // TODO implement
    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
