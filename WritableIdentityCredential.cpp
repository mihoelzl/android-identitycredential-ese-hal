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
using ::android::hardware::keymaster::capability::V1_0::CapabilityType;

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

static constexpr uint8_t kCLAProprietary = 0x80;
static constexpr uint8_t kINSCreateCredential = 0x10;
//static constexpr uint8_t kINSGetAttestationCertificate = 0x11;
static constexpr uint8_t kINSPersonalizeAccessControl = 0x12;
static constexpr uint8_t kINSPersonalizeNamespace = 0x13;
static constexpr uint8_t kINSPersonalizeAttribute = 0x14;
static constexpr uint8_t kINSSignPersonalizedData = 0x15;


WritableIdentityCredential::~WritableIdentityCredential(){
    ALOGD("IC Shutdown: closing open connections");
    if(mAppletConnection.isChannelOpen()){
        mAppletConnection.close();
    }
}

ResultCode WritableIdentityCredential::initializeCredential(const hidl_string& docType,
                                                       bool testCredential) {

    // Reste the current state 
    resetPersonalizationState();

    // Ensure doc size
    if(docType.size() > 255) {
        return ResultCode::INVALID_DATA;
    }

    mDocType = docType;
    mIsTestCredential = testCredential;

    return ResultCode::OK;
}

void WritableIdentityCredential::resetPersonalizationState(){

    mCredentialBlob.clear();

    mNamespaceEntries = hidl_vec<uint16_t>(0);
    mPersonalizationStarted = false;

    mCurrentNamespaceEntryCount = 0;
    mCurrentNamespaceId = 0;
    mCurrentNamespaceName.clear();

    mAccessControlProfilesPersonalized = 0;
    mAccessControlProfileCount = 0;
}

Return<void> WritableIdentityCredential::startPersonalization(const hidl_vec<uint8_t>& /* attestationApplicationId */,
                                  const hidl_vec<uint8_t>& /* attestationChallenge */,
                                  uint8_t accessControlProfileCount, uint16_t entryCount,
                                  startPersonalization_cb _hidl_cb) {
    ALOGD("Start personalization");

    hidl_vec<uint8_t> cert(180), credBlob;
    AuditLogHash auditLog;

    if (!mAppletConnection.connectToSEService()) {
        ALOGE("Error when connecting to SE service");
        _hidl_cb(ResultCode::IOERROR, cert, credBlob, auditLog);
        return Void();
    }

    ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
    if(!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK){
        ALOGE("Error selecting the applet ");
        _hidl_cb(ResultCode::FAILED, cert, credBlob, auditLog);
        return Void();
    }

    // Clear previous state 
    resetPersonalizationState();

    // Send the command to the applet to create a new credential
    CommandApdu command{kCLAProprietary,kINSCreateCredential,0,mIsTestCredential,mDocType.size(),256};
    std::string cred = mDocType;
    std::copy(cred.begin(), cred.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if(!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        _hidl_cb(swToErrorMessage(response), cert, credBlob, auditLog);
        return Void();
    } 

    ALOGD("Response: %s", bytes_to_hex(response.dataBegin(), response.dataEnd()).c_str());
    
    mCredentialBlob.assign(response.dataBegin(), response.dataEnd());

    mNamespaceEntries = hidl_vec<uint16_t>({entryCount});
    mAccessControlProfileCount = accessControlProfileCount;

    // TODO: generate and return attestation certificate
                                    
    mPersonalizationStarted = true;

    ALOGD("Credential initialized");
    
    _hidl_cb(ResultCode::OK, cert, mCredentialBlob, auditLog);
    return Void();
}

Return<void> WritableIdentityCredential::addAccessControlProfile(
    uint8_t id, const hidl_vec<uint8_t>& readerAuthPubKey, uint64_t capabilityId,
    const CapabilityType capabilityType, uint32_t timeout, addAccessControlProfile_cb _hidl_cb) {

    SecureAccessControlProfile result;
    if (!mAppletConnection.isChannelOpen()) {
        ALOGD("No connection to applet");
        _hidl_cb(ResultCode::IOERROR, result);
        return Void();
    }
    if(!mPersonalizationStarted){
        ALOGD("Personalization not started yet");
        _hidl_cb(ResultCode::IOERROR, result);
        return Void();
    }

    result.id = id;    

    // Set the number of profiles in p2
    uint8_t p1 = 0u;
    uint8_t p2 = mAccessControlProfileCount & 0xFF;

    // Buffer for CBOR encoded command data
    std::string buffer;

    // The size of the sent CBOR array depends on the specified authentication parameters
    size_t arraySize =
        1 + (readerAuthPubKey != 0u ? 1 : 0) + ((capabilityId != 0 ? (timeout != 0 ? 3 : 2) : 0));

    CborLite::encodeMapSize(buffer, arraySize);
    CborLite::encodeText(buffer, std::string("id"));
    CborLite::encodeInteger(buffer, id);

    // Check if reader authentication is specified
    if(readerAuthPubKey.size() != 0u){
        result.readerAuthPubKey.resize(readerAuthPubKey.size());

        std::copy(readerAuthPubKey.begin(), readerAuthPubKey.end(), result.readerAuthPubKey.begin());
        CborLite::encodeText(buffer, std::string("readerAuthPubKey"));
        CborLite::encodeBytes(buffer, readerAuthPubKey);
    }

    // Check if user authentication is specified
    if(capabilityId != 0u){
        result.capabilityId = capabilityId;
        result.capabilityType = capabilityType;
        result.timeout = timeout;
        CborLite::encodeText(buffer, std::string("userAuthTypes"));
        CborLite::encodeInteger(buffer, static_cast<uint32_t>(capabilityType));
        CborLite::encodeText(buffer, std::string("userSecureId"));
        CborLite::encodeInteger(buffer, capabilityId);

        // Check if timeout is set 
        if(timeout!=0){
            CborLite::encodeText(buffer, std::string("timeout"));
            CborLite::encodeInteger(buffer, timeout);
        }
    } else {
        result.capabilityId = 0u;
        result.capabilityType = CapabilityType::NOT_APPLICABLE;
        result.timeout = 0u;
    }

    // Data of command APDU is a CBOR array with the specified authentication parameters
    CommandApdu command{kCLAProprietary, kINSPersonalizeAccessControl, p1, p2, buffer.size(), 0};  
    std::copy(buffer.begin(), buffer.end(), command.dataBegin());    

    ResponseApdu response = mAppletConnection.transmit(command);

    // Check response
    if(response.ok() && response.status() == AppletConnection::SW_OK){
        std::string value;
        // Get the byte string in the response
        auto begin = response.dataBegin();
        auto end = response.dataEnd();

        auto len = CborLite::decodeEncodedBytes(begin, end, value);

        if(len == CborLite::INVALIDDATA){  
            _hidl_cb(ResultCode::INVALID_DATA, result);
            return Void();
        }

        result.mac.resize(len);
        std::copy(value.begin(), value.end(), result.mac.begin());

        mAccessControlProfilesPersonalized++;

        if(mAccessControlProfilesPersonalized == mAccessControlProfileCount){
            // TODO: remember the state
        } 
        _hidl_cb(ResultCode::OK, result);
    } else {
        _hidl_cb(swToErrorMessage(response), result);
    }

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
    if(!mPersonalizationStarted){
        ALOGD("Personalization not started yet");
        _hidl_cb(ResultCode::IOERROR, secureEntry, signature);
        return Void();
    }

    // Set the number of entries in p1p2
    uint8_t p1 = 0; 
    uint8_t p2 = 0; 
    std::string buffer;

    if(mCurrentNamespaceEntryCount == 0) {
        // New namespace needs to be started
        std::string newNamespaceName = std::string(entry.nameSpace);

        if(mCurrentNamespaceName.size() != 0) {
            // Sanity check: namespaces need to be sent in canonical CBOR format 
            //          * length of namespace name has to be in increasing order
            //          * if length is equal, namespaces need to be in lexographic order

            if(mCurrentNamespaceName.compare(newNamespaceName) > 0) {
                ALOGE("Canonical CBOR error: namespaces need to specified in (byte-wise) lexical order.");
                _hidl_cb(ResultCode::INVALID_DATA, secureEntry, signature);
                return Void();
            }
        }

        // Set the number of namespaces in p1p2
        p1 = (mNamespaceEntries.size() >> 8) & 0x3F;
        p2 = mNamespaceEntries.size() & 0xFF;
    
        mCurrentNamespaceName = newNamespaceName;
        mCurrentNamespaceEntryCount = mNamespaceEntries[mCurrentNamespaceId];

        CborLite::encodeArraySize(buffer, 2ul);
        CborLite::encodeInteger(buffer, mCurrentNamespaceEntryCount);
        CborLite::encodeText(buffer, mCurrentNamespaceName);

        CommandApdu command{kCLAProprietary, kINSPersonalizeNamespace, p1, p2, buffer.size(), 0};  
        std::copy(buffer.begin(), buffer.end(), command.dataBegin());  

        ResponseApdu response = mAppletConnection.transmit(command);

        if(response.ok() && response.status() == AppletConnection::SW_OK){
            mCurrentNamespaceId++;
            buffer.clear();

            ALOGD("New namespace successfully initialized");
        } else {
            ALOGE("Error during namespace initialization");
            _hidl_cb(swToErrorMessage(response), secureEntry, signature);
            return Void();
        }
    }

    // If this is a directly available entry, set the upper most flag
    if(entry.directlyAvailable){
        p1 = 0x80;
    } else {
        p1 = 0;
    }

    // Encode the entry as CBOR [Data, AdditionalData]
    CborLite::encodeArraySize(buffer, 2ul);

    // START Data entry 
    // TODO: current hidl-gen doesn't support unions
    CborLite::encodeText(buffer, std::string(entry.value));
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

    CommandApdu command{kCLAProprietary, kINSPersonalizeAttribute, p1, 0, buffer.size(), 0};  
    std::copy(buffer.begin(), buffer.end(), command.dataBegin());  
    
    ResponseApdu response = mAppletConnection.transmit(command);

    if(response.ok() && response.status() == AppletConnection::SW_OK){
        secureEntry.nameSpace = entry.nameSpace;
        secureEntry.name = entry.name;
        secureEntry.accessControlProfileIds = accessControlProfileIds;
        secureEntry.content.resize(response.dataSize());

        std::copy(response.dataBegin(), response.dataEnd(), secureEntry.content.begin());

        mCurrentNamespaceEntryCount--;

        // Check if this was the last entry in the last namespace
        if(mCurrentNamespaceEntryCount == 0 && mCurrentNamespaceId == mNamespaceEntries.size()){
            // Retrieve signedData 
            CommandApdu signDataCmd{kCLAProprietary, kINSSignPersonalizedData, 0, 0};    

            ResponseApdu signResponse = mAppletConnection.transmit(signDataCmd);
            if(signResponse.ok() && signResponse.status() == AppletConnection::SW_OK){
                signature.resize(signResponse.dataSize());
                
                std::copy(response.dataBegin(), response.dataEnd(), signature.begin());
            }

            // Finish personalization
            mPersonalizationStarted = false;
            mAppletConnection.close();

            _hidl_cb(swToErrorMessage(response), secureEntry, signature);
        } else {        
            ALOGD("Attribute successfully personalized: %s ", secureEntry.name.c_str());
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
