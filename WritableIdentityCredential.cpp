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

static constexpr uint8_t kCLAProprietary = 0x80;
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

ResultCode WritableIdentityCredential::initializeCredential(const hidl_string& credentialType,
                                                       bool testCredential) {

    if (!mAppletConnection.connectToSEService()) {
        ALOGD("Error when connecting");
        return ResultCode::IOERROR;
    }

    ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
    if(selectResponse.status() != 0x9000){
        return ResultCode::FAILED;
    }

    // Clear previous credentialBlob 
    mCredentialBlob.clear();

    // Send the command to the applet to create a new credential
    CommandApdu command{kCLAProprietary,kINSCreateCredential,0,testCredential,credentialType.size(),0};
    std::string cred = credentialType;
    std::copy(cred.begin(), cred.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if(!response.ok()){
        return ResultCode::IOERROR;
    } else if(response.isError()){
        return ResultCode::FAILED;
    }

    if(response.status() == 0x9000){
        ALOGD("Response: %s", bytes_to_hex(response.dataBegin(), response.dataEnd()).c_str());
        
        mCredentialBlob.assign(response.dataBegin(), response.dataEnd());
        
        return ResultCode::OK;
    }
    return ResultCode::INVALID_DATA;
}

Return<void> WritableIdentityCredential::startPersonalization(const hidl_vec<uint8_t>& /* attestationApplicationId */,
                                  const hidl_vec<uint8_t>& /* attestationChallenge */,
                                  uint8_t accessControlProfileCount, uint16_t entryCount,
                                  startPersonalization_cb _hidl_cb) {
    hidl_vec<uint8_t> cert, credBlob;
    AuditLogHash auditLog;
    if(mPersonalizationStarted){
        // Personalization already started once
        _hidl_cb(ResultCode::FAILED, cert, credBlob, auditLog);
        return Void();
    }

    mEntryCount = entryCount;
    mAccessControlProfileCount = accessControlProfileCount;

    // TODO: generate attestation certificate
                                    
    mPersonalizationStarted = true;
    return Void();
}

Return<void> WritableIdentityCredential::addAccessControlProfile(
    uint8_t /* id */, const hidl_vec<uint8_t>& /* readerAuthPubKey */, uint64_t /* capabilityId */,
    const ::android::hardware::keymaster::capability::V1_0::CapabilityType /* capabilityType */,
    uint32_t /* timeout */, addAccessControlProfile_cb /* _hidl_cb */) {
    // personalize(vec<AccessControlProfile> accessControlProfiles, vec<EntryConfiguration> entries)
    // generates(Error error, vec<uint8_t> credentialBlob,
    //                  vec<SecureAccessControlProfile> accessControlProfiles, vec<SecureEntry>
    //                  entries, vec<uint8_t> signedData);

    //ALOGD("%zu", sizeof(accessControlProfiles));
    //ALOGD("%zu", entries.size());



    //_hidl_cb(ResultCode::OK, NULL, NULL, NULL, NULL);

    mAppletConnection.close();

    // TODO implement
    return Void();
}

Return<void> WritableIdentityCredential::addEntry(const EntryData& /* entry */,
                                                  const hidl_vec<uint8_t>& /* accessControlProfileIds */,
                                                  addEntry_cb /* _hidl_cb */) {
    // TODO implement
    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
