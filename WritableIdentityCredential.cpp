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

#include <cn-cbor/cn-cbor.h>

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
    mAppletConnection.close();
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

    mCurrentValueEncryptedContent = 0;
    mCurrentValueEntrySize = 0;

    mAccessControlProfilesPersonalized = 0;
    mAccessControlProfileCount = 0;
}

bool WritableIdentityCredential::verifyAppletPersonalizationStatus(){

    if (!mAppletConnection.isChannelOpen()) {
        ALOGD("No connection to applet");
        return false;
    }
    if(!mPersonalizationStarted){
        ALOGD("Personalization not started yet");
        return false;
    }
    return true;
}


Return<void> WritableIdentityCredential::startPersonalization(const hidl_vec<uint8_t>& /* attestationApplicationId */,
                                  const hidl_vec<uint8_t>& /* attestationChallenge */,
                                  uint8_t accessControlProfileCount, uint16_t entryCount,
                                  startPersonalization_cb _hidl_cb) {
    ALOGD("Start personalization");

    hidl_vec<uint8_t> cert(180), credBlob;

    if (!mAppletConnection.connectToSEService()) {
        ALOGE("Error when connecting to SE service");
        _hidl_cb(ResultCode::IOERROR, cert, credBlob);
        return Void();
    }

    ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
    if(!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK){
        ALOGE("Error selecting the applet ");
        _hidl_cb(ResultCode::IOERROR, cert, credBlob);
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
        _hidl_cb(swToErrorMessage(response), cert, credBlob);
        mAppletConnection.close();
        return Void();
    } 
    
    unsigned long long arraySize = 0;
    bool auditLogHash = false; 
    std::string resultBlob;

    auto begin = response.dataBegin();
    auto end = response.dataEnd();

    auto len = CborLite::decodeArraySize(begin, end, arraySize);
    if(len == CborLite::INVALIDDATA){
        _hidl_cb(ResultCode::INVALID_DATA, cert, credBlob);
        return Void();
    }       

    // TODO: need to change that to byte string for auditloghash
    len = CborLite::decodeBool(begin, end, auditLogHash);
    if(len == CborLite::INVALIDDATA){
        _hidl_cb(ResultCode::INVALID_DATA, cert, credBlob);
        return Void();
    }

    len = CborLite::decodeBytes(begin, end, resultBlob);
    if(len == CborLite::INVALIDDATA){
        _hidl_cb(ResultCode::INVALID_DATA, cert, credBlob);
        return Void();
    }

    mCredentialBlob.assign(resultBlob.begin(), resultBlob.end());

    mNamespaceEntries = hidl_vec<uint16_t>({entryCount});
    mAccessControlProfileCount = accessControlProfileCount;

 
    // TODO: generate and return attestation certificate


    mPersonalizationStarted = true;                                  
    ALOGD("Credential initialized");
    
    _hidl_cb(ResultCode::OK, cert, mCredentialBlob);
    return Void();
}

Return<void> WritableIdentityCredential::addAccessControlProfile(
    uint8_t id, const hidl_vec<uint8_t>& readerAuthPubKey, uint64_t capabilityId,
    const CapabilityType capabilityType, uint32_t timeout, addAccessControlProfile_cb _hidl_cb) {

    SecureAccessControlProfile result;
    if (!verifyAppletPersonalizationStatus()) {
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

        auto len = CborLite::decodeBytes(begin, end, value);

        if(len == CborLite::INVALIDDATA){  
            _hidl_cb(ResultCode::INVALID_DATA, result);
            return Void();
        }

        result.mac.resize(value.size());

        std::copy(value.begin(), value.end(), result.mac.begin());

        mAccessControlProfilesPersonalized++;

        if(mAccessControlProfilesPersonalized == mAccessControlProfileCount){
            // TODO: Do we need to remember the state?
        } 
        _hidl_cb(ResultCode::OK, result);
    } else {
        _hidl_cb(swToErrorMessage(response), result);
    }

    return Void();
}

Return<ResultCode> WritableIdentityCredential::beginAddEntry(
        const hidl_vec<SecureAccessControlProfile>& accessControlProfiles,
        const hidl_string& nameSpace, const hidl_string& name, bool directlyAvailable,
        uint32_t entrySize) {
            
    if(!verifyAppletPersonalizationStatus()){
        return ResultCode::IOERROR;
    }

    // Set the number of entries in p1p2
    uint8_t p1 = 0; 
    uint8_t p2 = 0; 

    // Check if a new namespace has started
    if(mCurrentNamespaceEntryCount == 0) {
        std::string newNamespaceName = std::string(nameSpace);

        if(mCurrentNamespaceName.size() != 0) {
            // Sanity check: namespaces need to be sent in canonical CBOR format 
            //          * length of namespace name has to be in increasing order
            //          * if length is equal, namespaces need to be in lexographic order

            if(mCurrentNamespaceName.compare(newNamespaceName) > 0) {
                ALOGE("Canonical CBOR error: namespaces need to specified in (byte-wise) lexical order.");
                return ResultCode::INVALID_DATA;
            }
        }
        
        // Set the number of namespaces in p1p2
        p1 = (mNamespaceEntries.size() >> 8) & 0x3F;
        p2 = mNamespaceEntries.size() & 0xFF;
    
        mCurrentNamespaceName = newNamespaceName;
        mCurrentNamespaceEntryCount = mNamespaceEntries[mCurrentNamespaceId];
        
        cn_cbor* commandData =
                encodeCborNamespaceConf(mCurrentNamespaceName, mCurrentNamespaceEntryCount);

        if(commandData == nullptr){
           return ResultCode::INVALID_DATA;
        }
        
        CommandApdu command = createCommandApduFromCbor(kINSPersonalizeNamespace, p1, p2, commandData, 0);  
        ResponseApdu response = mAppletConnection.transmit(command);
        cn_cbor_free(commandData);

        if(response.ok() && response.status() == AppletConnection::SW_OK){
            mCurrentNamespaceId++;

            ALOGD("New namespace successfully initialized");
        } else {
            ALOGE("Error during namespace initialization");
            return swToErrorMessage(response);
        }
    }

    p1 = 0;
    p2 = 0;

    // If this is a directly available entry, set the upper most flag
    if(directlyAvailable){
        p1 |= 0x80;
    } 

    // Encode the additional data and send it to the applet
    cn_cbor* commandData = encodeCborAdditionalData(nameSpace, name, accessControlProfiles);

    if (commandData == nullptr) {
        ALOGE("Error initializing CBOR");
        return ResultCode::INVALID_DATA;
    }

    CommandApdu command = createCommandApduFromCbor(kINSPersonalizeAttribute, p1, p2, commandData, 0);  
    
    ResponseApdu response = mAppletConnection.transmit(command);

    if (response.ok() && response.status() == AppletConnection::SW_OK) {
        mCurrentValueEncryptedContent = 0;
        mCurrentValueEntrySize = entrySize;
        mCurrentValueDirectlyAvailable = directlyAvailable;
    }
    cn_cbor_free(commandData);
    return swToErrorMessage(response);
}

Return<void> WritableIdentityCredential::addEntryValue(const EntryValue& value, addEntryValue_cb _hidl_cb) {
    hidl_vec<uint8_t> encryptedVal; 

    if(!verifyAppletPersonalizationStatus()){
        _hidl_cb(ResultCode::IOERROR, encryptedVal);
        return Void();
    }
    
    uint8_t p1 = 0;  
    uint8_t p2 = 0; 
    std::string buffer;
    int64_t stringSize = -1;

    // START Data entry 
    switch(value.getDiscriminator()){
        case EntryValue::hidl_discriminator::integer:
            CborLite::encodeInteger(buffer, value.integer());
            break;
        case EntryValue::hidl_discriminator::textString:
            stringSize = value.textString().size();
            CborLite::encodeText(buffer, std::string(value.textString()));
            break;
        case EntryValue::hidl_discriminator::byteString:
            stringSize = value.byteString().size();
            CborLite::encodeBytes(buffer, value.byteString());
            break;
        case EntryValue::hidl_discriminator::booleanValue:
            CborLite::encodeBool(buffer, value.booleanValue());
            break;
        break;
        default:  // Should never happen
            ALOGE("Invalid data entry");
            _hidl_cb(ResultCode::INVALID_DATA, encryptedVal);
            return Void();
        break;
    }
    // END Data entry

    if (stringSize != -1) {
        if (stringSize != mCurrentValueEntrySize) {  // Chunking
            p1 |= 0x4;                               // Bit 3 indicates chunking
            if (mCurrentValueEncryptedContent != 0) {
                p1 |= 0x2;  // Bit 2 indicates a chunk "inbetween"
            }
        }

        mCurrentValueEncryptedContent += stringSize;

        // Validate that the entry is not too large
        if (mCurrentValueEncryptedContent > mCurrentValueEntrySize) {
            ALOGE("Entry value is exceeding the defined entry size");
            _hidl_cb(ResultCode::INVALID_DATA, encryptedVal);
            return Void();
        } else if (mCurrentValueEncryptedContent != mCurrentValueEntrySize &&
                   stringSize != mAppletConnection.chunkSize()) {
            ALOGE("Entry size does not match chunk size");
            _hidl_cb(ResultCode::INVALID_DATA, encryptedVal);
            return Void();
        } 
    } 

    if(mCurrentValueDirectlyAvailable){
        p1 |= 0x80; // Bit 8 indicates if this is a directly available entry
    }
    if (stringSize == -1 || mCurrentValueEncryptedContent == mCurrentValueEntrySize){
        p1 |= 0x1; // Indicates that this is the last (or only) value in chain
    }

    CommandApdu command{kCLAProprietary, kINSPersonalizeAttribute, p1, p2, buffer.size(), 0};  
    std::copy(buffer.begin(), buffer.end(), command.dataBegin());  
            
    ResponseApdu response = mAppletConnection.transmit(command);

    if (response.ok() && response.status() == AppletConnection::SW_OK) {
        encryptedVal.resize(response.dataSize());

        std::copy(response.dataBegin(), response.dataEnd(), encryptedVal.begin());

        if (stringSize == -1 || mCurrentValueEncryptedContent == mCurrentValueEntrySize) {
            // Finish this entry
            mCurrentNamespaceEntryCount--;
        }
    }

    _hidl_cb(swToErrorMessage(response), encryptedVal);
    return Void();
}

Return<void> WritableIdentityCredential::finishAddingEntryies(finishAddingEntryies_cb _hidl_cb) {
    hidl_vec<uint8_t> signature; 

    if(!verifyAppletPersonalizationStatus()){
        _hidl_cb(ResultCode::IOERROR, signature);
        return Void();
    }

    // Check if this was the last entry in the last namespace
    if(mCurrentNamespaceEntryCount == 0 && mCurrentNamespaceId == mNamespaceEntries.size()){
        // Retrieve signedData 
        CommandApdu signDataCmd{kCLAProprietary, kINSSignPersonalizedData, 0, 0};    

        ResponseApdu signResponse = mAppletConnection.transmit(signDataCmd);
        if(signResponse.ok() && signResponse.status() == AppletConnection::SW_OK){
            signature.resize(signResponse.dataSize());
            
            std::copy(signResponse.dataBegin(), signResponse.dataEnd(), signature.begin());
        }

        // Finish personalization
        mPersonalizationStarted = false;
        mAppletConnection.close();

        _hidl_cb(swToErrorMessage(signResponse), signature);
    } else {
        ALOGD("Missing entries to personalize. Personalization state (%d/%d) ",
              mNamespaceEntries[mCurrentNamespaceId] - mCurrentNamespaceEntryCount,
              mNamespaceEntries[mCurrentNamespaceId]);
        _hidl_cb(ResultCode::OK, signature);
    }
    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
