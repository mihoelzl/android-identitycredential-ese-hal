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
    mAppletConnection.close();
}

ResultCode WritableIdentityCredential::initializeCredential(const hidl_string& docType,
                                                       bool testCredential) {

    // Reste the current state 
    resetPersonalizationState();

    // Check docType size
    if(docType.size() > 255) {
        return ResultCode::INVALID_DATA;
    }

    mDocType = docType;
    mIsTestCredential = testCredential;

    return ResultCode::OK;
}

void WritableIdentityCredential::resetPersonalizationState(){

    mCredentialBlob.clear();
    mPersonalizationStarted = false;

    mCurrentNamespaceEntryCount = 0;
    mCurrentNamespaceId = 0;
    
    mCurrentValueEncryptedContent = 0;
    mCurrentValueEntrySize = 0;

    mAccessControlProfilesPersonalized = 0;
}

bool WritableIdentityCredential::verifyAppletPersonalizationStatus() {
    if (!mAppletConnection.isChannelOpen()) {
        ALOGE("No connection to applet");
        return false;
    }
    if(!mPersonalizationStarted){
        ALOGE("Personalization not started yet");
        return false;
    }
    return true;
}

Return<void> WritableIdentityCredential::getAttestationCertificate(
        const hidl_vec<uint8_t>& /* attestationApplicationId */,
        const hidl_vec<uint8_t>& /* attestationChallenge */,
        getAttestationCertificate_cb _hidl_cb) {
    hidl_vec<uint8_t> cert(180);
    _hidl_cb(ResultCode::OK, cert);
    return Void();
}

Return<ResultCode> WritableIdentityCredential::startPersonalization(
                                  uint8_t accessControlProfileCount, const hidl_vec<uint16_t>& entryCounts) {
    if (!mAppletConnection.connectToSEService()) {
        ALOGE("[%s] : Error while trying to connect to SE service.", __func__);
        return ResultCode::IOERROR;
    }

    // Initiate communication to applet 
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            ALOGE("[%s] : Could not select the applet. ", __func__);
            return swToErrorMessage(selectResponse);
        }
    }

    if(entryCounts.size() <= 0){
        ALOGE("[%s] : Nothing to personalize.", __func__);
        return ResultCode::INVALID_DATA;
    }

    // Clear previous state if existing
    resetPersonalizationState();

    // Send the command to the applet to create a new credential
    CommandApdu command{kCLAProprietary,   kINSCreateCredential, 0,
                        mIsTestCredential, mDocType.size(),      256};
    std::string cred = mDocType;
    std::copy(cred.begin(), cred.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return swToErrorMessage(response);
    } 
    
    std::string resultBlob;

    auto begin = response.dataBegin();
    auto end = response.dataEnd();

    auto len = CborLite::decodeBytes(begin, end, resultBlob);
    if(len == CborLite::INVALIDDATA){
        return ResultCode::INVALID_DATA;
    }

    mCredentialBlob.assign(resultBlob.begin(), resultBlob.end());

    mNamespaceEntries = entryCounts;
    mAccessControlProfileCount = accessControlProfileCount;

    mPersonalizationStarted = true;

    return ResultCode::OK;
}

Return<void> WritableIdentityCredential::addAccessControlProfile(
    uint8_t id, const hidl_vec<uint8_t>& readerAuthPubKey, uint64_t capabilityId,
    const CapabilityType capabilityType, uint32_t timeout, addAccessControlProfile_cb _hidl_cb) {

    SecureAccessControlProfile result;
    if (!verifyAppletPersonalizationStatus()) {
        ALOGE("[%s] : Personalization not started yet.", __func__);
        _hidl_cb(ResultCode::IOERROR, result);
        return Void();
    }

    // Set the number of profiles in p2
    uint8_t p1 = 0u;
    uint8_t p2 = mAccessControlProfileCount & 0xFF;

    result.id = id;    

    // Check if reader authentication is specified
    if(readerAuthPubKey.size() != 0u){
        result.readerAuthPubKey = readerAuthPubKey;
    }

    // Check if user authentication is specified
    if(capabilityId != 0u){
        result.capabilityId = capabilityId;
        result.capabilityType = capabilityType;
        result.timeout = timeout;
    } else {
        result.capabilityId = 0u;
        result.capabilityType = CapabilityType::NOT_APPLICABLE;
        result.timeout = 0u;
    }

    cn_cbor_errback err;
    cn_cbor* acp = encodeCborAccessControlProfile(id, readerAuthPubKey,
                                                    capabilityId, capabilityType, 
                                                    timeout);

    if (acp == nullptr) {
        ALOGE("[%s] : Error in access control profile CBOR initalization. ", __func__);
        _hidl_cb(ResultCode::INVALID_DATA, result);
        return Void();
    }

    // Data of command APDU is a CBOR array with the specified authentication parameters
    // Send command
    CommandApdu command =
            createCommandApduFromCbor(kINSPersonalizeAccessControl, p1, p2, acp, &err);
    cn_cbor_free(acp);

    if(err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error in access control profile CBOR initalization. ", __func__);
        _hidl_cb(ResultCode::INVALID_DATA, result);
        return Void();
    }

    ResponseApdu response = mAppletConnection.transmit(command);

    // Check response
    if(!response.ok() || response.status() != AppletConnection::SW_OK){
        _hidl_cb(swToErrorMessage(response), result);
        return Void();
    }

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

    _hidl_cb(ResultCode::OK, result);

    return Void();
}

Return<ResultCode> WritableIdentityCredential::beginAddEntry(
        const hidl_vec<uint8_t>& accessControlProfiles,
        const hidl_string& nameSpace, const hidl_string& name, bool directlyAvailable,
        uint32_t entrySize) {
            
    if(!verifyAppletPersonalizationStatus()){
        ALOGE("[%s] : Personalization not started yet.", __func__);
        return ResultCode::IOERROR;
    }

    if (mAccessControlProfilesPersonalized != mAccessControlProfileCount) {
        ALOGE("[%s] : Need to finish access control profile configuration first.", __func__);
        return ResultCode::INVALID_DATA;
    } 

    // Set the number of entries in p1p2
    uint8_t p1 = 0; 
    uint8_t p2 = 0; 

    cn_cbor_errback err;

    // Check if a new namespace has started
    if(mCurrentNamespaceEntryCount == 0) {

        // Set the number of namespaces in p1p2
        p1 = (mNamespaceEntries.size() >> 8) & 0x3F;
        p2 = mNamespaceEntries.size() & 0xFF;
    
        mCurrentNamespaceEntryCount = mNamespaceEntries[mCurrentNamespaceId];
        
        cn_cbor* commandData =
                encodeCborNamespaceConf(nameSpace, mCurrentNamespaceEntryCount);

        if (commandData == nullptr) {
            return ResultCode::INVALID_DATA;
        }

        CommandApdu command =
                createCommandApduFromCbor(kINSPersonalizeNamespace, p1, p2, commandData, &err);

        if (err.err != CN_CBOR_NO_ERROR) {
            cn_cbor_free(commandData);
            return ResultCode::INVALID_DATA;
        }

        ResponseApdu response = mAppletConnection.transmit(command);
        cn_cbor_free(commandData);

        if(response.ok() && response.status() == AppletConnection::SW_OK){
            mCurrentNamespaceId++;
        } else {
            ALOGE("[%s] : Error during namespace initialization", __func__);
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
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    CommandApdu command = createCommandApduFromCbor(kINSPersonalizeAttribute, p1, p2, commandData, &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        cn_cbor_free(commandData);
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }
    
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
        ALOGE("[%s] : Personalization not started yet.", __func__);
        _hidl_cb(ResultCode::IOERROR, encryptedVal);
        return Void();
    }
    
    uint8_t p1 = 0;  
    uint8_t p2 = 0; 
    int64_t stringSize = -1;

    cn_cbor_errback err;
    cn_cbor* commandData = nullptr;

    // START Data entry 
    switch(value.getDiscriminator()){
        case EntryValue::hidl_discriminator::integer:
            commandData = cn_cbor_int_create(value.integer(), &err);
            break;
        case EntryValue::hidl_discriminator::textString:
            stringSize = value.textString().size();
            commandData = cn_cbor_string_create(value.textString().c_str(), &err);
            break;
        case EntryValue::hidl_discriminator::byteString:
            stringSize = value.byteString().size();
            commandData = cn_cbor_data_create(&(*value.byteString().begin()), stringSize, &err);
            break;
        case EntryValue::hidl_discriminator::booleanValue:
            commandData = encodeCborBoolean(value.booleanValue(), &err);
            break;
        break;
        default:  // Should never happen
            ALOGE("[%s] : Invalid data entry", __func__);
            _hidl_cb(ResultCode::INVALID_DATA, encryptedVal);
            return Void();
        break;
    }
    // END Data entry

    if (commandData == nullptr || err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        _hidl_cb(ResultCode::INVALID_DATA, encryptedVal);
        return Void();
    }

    if(mCurrentValueDirectlyAvailable){
        p1 |= 0x80; // Bit 8 indicates if this is a directly available entry
    }
    
    std::vector<uint8_t> buffer;
    buffer = encodeCborAsVector(commandData, &err);

    if (stringSize != -1) {
        if (stringSize != mCurrentValueEntrySize) {  // Chunking
            p1 |= 0x4;                               // Bit 3 indicates chunking
            
            if (mCurrentValueEncryptedContent == 0) {
                // First chunk, need to encode the full length at the beginning
                cn_cbor* entrySize = cn_cbor_int_create(mCurrentValueEntrySize, &err);
                std::vector<uint8_t> encodedEntrySize = encodeCborAsVector(entrySize, &err);
                cn_cbor_free(entrySize);

                // Major type from data buffer
                encodedEntrySize[0] &= 0x1F;
                encodedEntrySize[0] |= buffer[0] & 0xE0;

                // Copy type and length to buffer
                if(encodedEntrySize.size() + stringSize > buffer.size()){
                    uint8_t diff = buffer.size() - (encodedEntrySize.size() + stringSize);
                    buffer.resize(encodedEntrySize.size() + stringSize);
                    std::rotate(buffer.begin(), buffer.end() - diff, buffer.end());
                }

                std::copy(encodedEntrySize.begin(), encodedEntrySize.end(), buffer.begin());  
            } else { // 
                p1 |= 0x2;  // Bit 2 indicates a chunk "inbetween"
            }
        }

        mCurrentValueEncryptedContent += stringSize;

        // Validate that the entry is not too large
        if (mCurrentValueEncryptedContent > mCurrentValueEntrySize) {
            ALOGE("[%s] : Entry value is exceeding the defined entry size", __func__);
            _hidl_cb(ResultCode::INVALID_DATA, encryptedVal);
            return Void();
        } else if (mCurrentValueEncryptedContent != mCurrentValueEntrySize &&
                   stringSize != mAppletConnection.chunkSize()) {
            ALOGE("[%s] : Entry size does not match chunk size", __func__);
            _hidl_cb(ResultCode::INVALID_DATA, encryptedVal);
            return Void();
        } 
    } 

    if (stringSize == -1 || mCurrentValueEncryptedContent == mCurrentValueEntrySize){
        p1 |= 0x1; // Indicates that this is the last (or only) value in chain
    }
    
    CommandApdu command{kCLAProprietary, kINSPersonalizeAttribute, p1, p2, buffer.size(), 0};  
    std::copy(buffer.begin(), buffer.end(), command.dataBegin());  
            
    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response), encryptedVal);
        return Void();
    }

    encryptedVal.resize(response.dataSize());

    std::copy(response.dataBegin(), response.dataEnd(), encryptedVal.begin());

    if (stringSize == -1 || mCurrentValueEncryptedContent == mCurrentValueEntrySize) {
        // Finish this entry
        mCurrentNamespaceEntryCount--;
    }

    _hidl_cb(ResultCode::OK, encryptedVal);
    return Void();
}

Return<void> WritableIdentityCredential::finishAddingEntries(finishAddingEntries_cb _hidl_cb) {
    hidl_vec<uint8_t> signature; 

    if(!verifyAppletPersonalizationStatus()){
        ALOGE("[%s] : Personalization not started yet.", __func__);
        _hidl_cb(ResultCode::IOERROR, signature, signature);
        return Void();
    }

    // Check if this was the last entry in the last namespace
    if(mCurrentNamespaceEntryCount != 0 || mCurrentNamespaceId != mNamespaceEntries.size()){
        ALOGD("Missing entries to personalize. Personalization state (%d/%d) ",
              mNamespaceEntries[mCurrentNamespaceId] - mCurrentNamespaceEntryCount,
              mNamespaceEntries[mCurrentNamespaceId]);
        _hidl_cb(ResultCode::INVALID_DATA, signature, signature);
        return Void();
    }

    // Retrieve signedData 
    CommandApdu signDataCmd{kCLAProprietary, kINSSignPersonalizedData, 0, 0};    

    ResponseApdu signResponse = mAppletConnection.transmit(signDataCmd);
    if(signResponse.ok() && signResponse.status() == AppletConnection::SW_OK){
        // Success, prepare return data
        cn_cbor_errback err;
        cn_cbor* credentialData = cn_cbor_array_create(&err);
        std::vector<uint8_t> resultCredData;

        if (cn_cbor_array_append(credentialData, cn_cbor_string_create(mDocType.c_str(), &err), &err) &&
            cn_cbor_array_append(credentialData, encodeCborBoolean(mIsTestCredential, &err), &err) &&
            cn_cbor_array_append(credentialData, cn_cbor_data_create(mCredentialBlob.data(), 
                    mCredentialBlob.size(), &err), &err)) {

            // Return values
            signature.resize(signResponse.dataSize());
            std::copy(signResponse.dataBegin(), signResponse.dataEnd(), signature.begin());

            resultCredData = encodeCborAsVector(credentialData, &err);

            if(err.err == CN_CBOR_NO_ERROR){
                _hidl_cb(ResultCode::OK, resultCredData, signature);
            } else {
                _hidl_cb(ResultCode::INVALID_DATA, resultCredData, signature);
            }
        } else {
            _hidl_cb(ResultCode::INVALID_DATA, resultCredData, signature);
        }
    } else {
        _hidl_cb(swToErrorMessage(signResponse), signature, signature);
    }

    // Finish personalization
    mPersonalizationStarted = false;
    mAppletConnection.close();

    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
