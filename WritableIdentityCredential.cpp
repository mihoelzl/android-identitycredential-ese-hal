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
#include "CborLiteCodec.h"
#include "ICUtils.h"


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
//static constexpr uint8_t kINSPersonalizeNamespace = 0x13;
static constexpr uint8_t kINSPersonalizeAttribute = 0x14;
static constexpr uint8_t kINSSignPersonalizedData = 0x15;


WritableIdentityCredential::~WritableIdentityCredential(){
    ALOGD("IC Shutdown: closing open connections");
    if(mAppletConnection.isChannelOpen()){
        mAppletConnection.close();
    }
}

ResultCode WritableIdentityCredential::initializeCredential(const hidl_string& credentialType,
                                                       bool testCredential) {

    if (!mAppletConnection.connectToSEService()) {
        ALOGE("Error when connecting");
        return ResultCode::IOERROR;
    }

    ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
    if(!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK){
        return ResultCode::FAILED;
    }

    ALOGD("Trying to initialize Applet");
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
        
        mPersonalizationStarted = false;

        return ResultCode::OK;
    }
    return ResultCode::INVALID_DATA;
}

Return<void> WritableIdentityCredential::startPersonalization(const hidl_vec<uint8_t>& /* attestationApplicationId */,
                                  const hidl_vec<uint8_t>& /* attestationChallenge */,
                                  uint8_t accessControlProfileCount, uint16_t entryCount,
                                  startPersonalization_cb _hidl_cb) {
    ALOGD("Start personalization");

    hidl_vec<uint8_t> cert(180), credBlob;
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
    
    _hidl_cb(ResultCode::OK, cert, mCredentialBlob, auditLog);
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

    // mAppletConnection.close();

    // TODO implement
    return Void();
}

Return<void> WritableIdentityCredential::addEntry(const EntryData& entry,
                                                  const hidl_vec<uint8_t>& accessControlProfileIds,
                                                  addEntry_cb _hidl_cb) {
    SecureEntry secureEntry;
    hidl_vec<uint8_t> signature; 

    if (!mAppletConnection.isChannelOpen()) {
        ALOGD("No connection to applet");
        _hidl_cb(ResultCode::IOERROR, secureEntry, signature);
        return Void();
    }

    // Set the number of entries in p1p2
    uint8_t p1 = (mEntryCount >> 8) & 0x3F;
    uint8_t p2 = mEntryCount & 0xFF;

    // If this is a directly available entry, set the upper most flag
    if(entry.directlyAvailable){
        p1 |= 0x80;
    }

    // Encode the entry as CBOR [Data, AdditionalData]
    std::string buffer;
    CborLite::encodeArraySize(buffer, 2ul);

    // START Data entry 
    // TODO: current hidl-gen doesn't support unions
    CborLite::encodeBool(buffer, entry.value.booleanValue);
    // END Data entry 

    // START Map for AdditionalData (3 entries)
    CborLite::encodeMapSize(buffer, 3ul);

    CborLite::encodeText(buffer, std::string("namespace"));
    CborLite::encodeText(buffer, std::string(entry.nameSpace));

    CborLite::encodeText(buffer, std::string("name"));
    CborLite::encodeText(buffer, std::string(entry.name));

    CborLite::encodeText(buffer, std::string("accessControlProfileIds"));
    CborLite::encodeArraySize(buffer, accessControlProfileIds.size());
    for(size_t i = 0; i<accessControlProfileIds.size(); i++){
        CborLite::encodeInteger(buffer, accessControlProfileIds[i]);
    }
    // END AdditionalData

    CommandApdu command{kCLAProprietary, kINSPersonalizeAttribute, p1, p2, buffer.size(), 0};    
    
    ResponseApdu response = mAppletConnection.transmit(command);

    if(response.ok() && response.status() == AppletConnection::SW_OK){
        secureEntry.nameSpace = entry.nameSpace;
        secureEntry.name = entry.name;
        secureEntry.accessControlProfileIds = accessControlProfileIds;
        secureEntry.content.resize(response.dataSize());

        std::copy(response.dataBegin(), response.dataEnd(), secureEntry.content.begin());

        mEntriesPersonalized++;

        if(mEntriesPersonalized == mEntryCount){
            // Retrieve signedData 
            CommandApdu signDataCmd{kCLAProprietary, kINSSignPersonalizedData, 0, 0};    

            ResponseApdu signResponse = mAppletConnection.transmit(signDataCmd);
            if(signResponse.ok() && signResponse.status() == AppletConnection::SW_OK){
                // TODO: check and return the result. 
            }
        } else {        
            _hidl_cb(ResultCode::OK, secureEntry, signature);
        }
    } else {
        _hidl_cb(swToErrorMessage(response), secureEntry, signature);
    }
    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
