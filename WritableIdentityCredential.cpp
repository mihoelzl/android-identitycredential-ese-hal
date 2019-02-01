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
static constexpr uint8_t kINSGetAttestationCertificate = 0x11;
static constexpr uint8_t kINSPersonalizeAccessControl = 0x12;
static constexpr uint8_t kINSPersonalizeNamespace = 0x13;
static constexpr uint8_t kINSPersonalizeAttribute = 0x14;
static constexpr uint8_t kINSSignPersonalizedData = 0x15;

static constexpr uint8_t kMaxAttestChallengeSize = 8;

WritableIdentityCredential::~WritableIdentityCredential(){
    mAppletConnection.close();
}

Result WritableIdentityCredential::initializeCredential(const hidl_string& docType,
                                                       bool testCredential) {
    if (!mAppletConnection.connectToSEService()) {
        return result(ResultCode::FAILED, "Error while trying to connect to SE service.");
    }

    // Initiate communication to applet
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            return result(ResultCode::FAILED, "Could not select the applet. ");
        }
    }

    // Reste the current state
    resetPersonalizationState();

    // Check docType size
    if (docType.size() > 255) {
        return result(ResultCode::INVALID_DATA, "DocType string too long.");
    }

    mDocType = docType;
    mIsTestCredential = testCredential;

    // Send the command to the applet to create a new credential
    CommandApdu command{kCLAProprietary,   kINSCreateCredential, 0,
                        mIsTestCredential, mDocType.size(),      256};
    std::string cred = mDocType;
    std::copy(cred.begin(), cred.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || (response.status() != AppletConnection::SW_OK)) {
        mAppletConnection.close();
        return swToErrorMessage(response, "Error initializing credential");
    }

    cn_cbor_errback err;
    auto cbor_resultBlob = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));
    
    if(cbor_resultBlob.get() == nullptr || cbor_resultBlob.get()->type != CN_CBOR_BYTES){
        return result(ResultCode::INVALID_DATA, "SE response could not be decoded.");
    }

    auto len = cbor_resultBlob.get()->length;

    mCredentialBlob.resize(len);
    std::copy(cbor_resultBlob.get()->v.bytes, cbor_resultBlob.get()->v.bytes + len,
              mCredentialBlob.begin());

    return resultOk();
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
    if (!mPersonalizationStarted) {
        ALOGE("Personalization not started yet");
        return false;
    }
    return true;
}

Return<void> WritableIdentityCredential::getAttestationCertificate(
        const hidl_vec<uint8_t>& attestationChallenge,
        getAttestationCertificate_cb _hidl_cb) {
    hidl_vec<uint8_t> cert;
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(result(ResultCode::FAILED, "Could not select the applet. "), cert);
            return Void();
        }
    }

    cn_cbor_errback err;

    if (attestationChallenge.size() > kMaxAttestChallengeSize) {
        _hidl_cb(result(ResultCode::INVALID_DATA,
                        "Challenge is too large. Maximum length is %d bytes. ",
                        kMaxAttestChallengeSize),
                 cert);
        return Void();
    }

    // Request for the attestation certificate 
    CommandApdu command{kCLAProprietary, kINSGetAttestationCertificate, 0, 0, kMaxAttestChallengeSize, 0};
    std::copy(attestationChallenge.begin(), attestationChallenge.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response, "Attestation certificate creation failed. "), cert);
        return Void();
    }

    auto cbor_attestCert = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));
    if (cbor_attestCert.get() == nullptr || cbor_attestCert.get()->type != CN_CBOR_BYTES ) {
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response. "), cert);
        return Void();
    }

    cert.resize(cbor_attestCert->length);

    std::copy(cbor_attestCert->v.bytes, cbor_attestCert->v.bytes + cbor_attestCert->length,
              cert.begin());

    _hidl_cb(resultOk(), cert);
    return Void();
}

Return<void> WritableIdentityCredential::startPersonalization(uint8_t accessControlProfileCount,
                                                              const hidl_vec<uint16_t>& entryCounts,
                                                              startPersonalization_cb _hidl_cb) {
    // Initiate communication to applet
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(result(ResultCode::FAILED, "Could not select the applet. "));
            return Void();
        }
    }

    if (entryCounts.size() <= 0) {
        _hidl_cb(result(ResultCode::INVALID_DATA, "Nothing to personalize."));
        return Void();
    }

    mNamespaceEntries = entryCounts;
    mAccessControlProfileCount = accessControlProfileCount;

    mPersonalizationStarted = true;

    _hidl_cb(resultOk());
    return Void();
}

Return<void> WritableIdentityCredential::addAccessControlProfile(
    uint8_t id, const hidl_vec<uint8_t>& readerCertificate, uint64_t capabilityId,
    const CapabilityType capabilityType, uint32_t timeout, addAccessControlProfile_cb _hidl_cb) {
    SecureAccessControlProfile acpResult;
    if (!verifyAppletPersonalizationStatus()) {
        _hidl_cb(result(ResultCode::FAILED, "Personalization not started yet. "), acpResult);
        return Void();
    }

    // Set the number of profiles in p2
    uint8_t p1 = 0u;
    uint8_t p2 = mAccessControlProfileCount & 0xFF;

    acpResult.id = id;

    // Check if reader authentication is specified
    if (readerCertificate.size() != 0u) {
        if (getECPublicKeyFromCertificate(readerCertificate).size() == 0) {
            _hidl_cb(result(ResultCode::INVALID_DATA, "Certificate parsing error."), acpResult);
            return Void();
        }
        acpResult.readerCertificate = readerCertificate;
    }

    // Check if user authentication is specified
    if (capabilityId != 0u) {
        acpResult.capabilityId = capabilityId;
        acpResult.capabilityType = capabilityType;
        acpResult.timeout = timeout;
    } else {
        acpResult.capabilityId = 0u;
        acpResult.capabilityType = CapabilityType::NOT_APPLICABLE;
        acpResult.timeout = 0u;
    }

    cn_cbor_errback err;
    auto acp = CBORPtr(
            encodeCborAccessControlProfile(id, getECPublicKeyFromCertificate(readerCertificate),
                                           capabilityId, capabilityType, timeout));

    if (acp.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED,
                        "Error encoding the access control profile as CBOR. "),
                 acpResult);
        return Void();
    }

    // Data of command APDU is a CBOR array with the specified authentication parameters
    // Send command
    CommandApdu command =
            createCommandApduFromCbor(kINSPersonalizeAccessControl, p1, p2, acp.get(), &err);

    if (err.err != CN_CBOR_NO_ERROR) {
        _hidl_cb(result(ResultCode::FAILED,
                        "Error encoding the access control profile as CBOR. "),
                 acpResult);
        return Void();
    }

    ResponseApdu response = mAppletConnection.transmit(command);

    // Check response
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response, "Error personalizing access control profile"), acpResult);
        return Void();
    }

    // Get the byte string in the response
    auto cbor_mac = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));
    
    if(cbor_mac.get() == nullptr || cbor_mac.get()->type != CN_CBOR_BYTES){
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response. "), acpResult);
        return Void();
    }

    auto len = cbor_mac.get()->length;

    acpResult.mac.resize(len);
    std::copy(cbor_mac.get()->v.bytes, cbor_mac.get()->v.bytes + len, acpResult.mac.begin());

    mAccessControlProfilesPersonalized++;

    _hidl_cb(resultOk(), acpResult);

    return Void();
}

Return<void> WritableIdentityCredential::beginAddEntry(
        const hidl_vec<uint8_t>& accessControlProfiles, const hidl_string& nameSpace,
        const hidl_string& name, bool directlyAvailable, uint32_t entrySize,
        beginAddEntry_cb _hidl_cb) {
    if (!verifyAppletPersonalizationStatus()) {
        _hidl_cb(result(ResultCode::FAILED, "Personalization not started yet. "));
        return Void();
    }

    if (mAccessControlProfilesPersonalized != mAccessControlProfileCount) {
        _hidl_cb(result(ResultCode::FAILED,
                        "Need to finish access control profile configuration first. "));
        return Void();
    } 

    // Set the number of entries in p1p2
    uint8_t p1 = 0; 
    uint8_t p2 = 0; 

    cn_cbor_errback err;

    // Check if a new namespace has started
    if (mCurrentNamespaceEntryCount == 0 && mCurrentNamespaceName != nameSpace) {
        // Set the number of namespaces in p1p2
        p1 = (mNamespaceEntries.size() >> 8) & 0x3F;
        p2 = mNamespaceEntries.size() & 0xFF;

        mCurrentNamespaceEntryCount = mNamespaceEntries[mCurrentNamespaceId];

        auto commandData =
                CBORPtr(encodeCborNamespaceConf(nameSpace, mCurrentNamespaceEntryCount));

        if (commandData.get() == nullptr) {
            _hidl_cb(result(ResultCode::INVALID_DATA, "Error encoding namespace."));
            return Void();
        }

        CommandApdu command = createCommandApduFromCbor(kINSPersonalizeNamespace, p1, p2,
                                                        commandData.get(), &err);

        if (err.err != CN_CBOR_NO_ERROR) {
            _hidl_cb(result(ResultCode::FAILED, "Error encoding new CBOR structure."));
            return Void();
        }

        ResponseApdu response = mAppletConnection.transmit(command);

        if (response.ok() && response.status() == AppletConnection::SW_OK) {
            mCurrentNamespaceName = nameSpace;
            mCurrentNamespaceId++;
        } else {
            _hidl_cb(swToErrorMessage(response, "Error during namespace initialization"));
            return Void();
        }
    } else if (mCurrentNamespaceName != nameSpace) {
        _hidl_cb(result(ResultCode::FAILED,
                        "Cannot start a new namespace, %hu entries remain to be added.",
                        mCurrentNamespaceEntryCount));
        return Void();
    } else if (mCurrentNamespaceEntryCount == 0) {
        _hidl_cb(result(ResultCode::FAILED,
                        "No more entries remain to be added for this namespace."));
        return Void();
    }

    p1 = 0;
    p2 = 0;

    // If this is a directly available entry, set the upper most flag
    if (directlyAvailable) {
        p1 |= 0x80;
    }

    // Encode the additional data and send it to the applet
    auto commandData =
                CBORPtr(encodeCborAdditionalData(nameSpace, name, accessControlProfiles));

    if (commandData.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error encoding additional data as CBOR."));
        return Void();
    }

    CommandApdu command =
            createCommandApduFromCbor(kINSPersonalizeAttribute, p1, p2, commandData.get(), &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        _hidl_cb(result(ResultCode::FAILED, "Error encoding additional data as CBOR."));
        return Void();
    }
    
    ResponseApdu response = mAppletConnection.transmit(command);

    if (response.ok() && response.status() == AppletConnection::SW_OK) {
        mCurrentValueEncryptedContent = 0;
        mCurrentValueEntrySize = entrySize;
        mCurrentValueDirectlyAvailable = directlyAvailable;
    }
    _hidl_cb(swToErrorMessage(response, ""));
    return Void();
}

Return<void> WritableIdentityCredential::addEntryValue(const EntryValue& value,
                                                       addEntryValue_cb _hidl_cb) {
    hidl_vec<uint8_t> encryptedVal;

    if (!verifyAppletPersonalizationStatus()) {
        _hidl_cb(result(ResultCode::FAILED, "Personalization not started yet. "), encryptedVal);
        return Void();
    }
    
    uint8_t p1 = 0;  
    uint8_t p2 = 0; 
    int64_t stringSize = -1;

    cn_cbor_errback err;
    auto cmdData = CBORPtr(nullptr);

    // START Data entry 
    switch(value.getDiscriminator()){
        case EntryValue::hidl_discriminator::integer:
            cmdData = CBORPtr(cn_cbor_int_create(value.integer(), &err));
            break;
        case EntryValue::hidl_discriminator::textString:
            stringSize = value.textString().size();

            cmdData = CBORPtr(cn_cbor_string_create((char*) value.textString().data(), &err));
            cmdData.get()->length = stringSize;
            break;
        case EntryValue::hidl_discriminator::byteString:
            stringSize = value.byteString().size();
            cmdData = CBORPtr(cn_cbor_data_create(value.byteString().data(), stringSize, &err));
            break;
        case EntryValue::hidl_discriminator::booleanValue:
            cmdData = CBORPtr(encodeCborBoolean(value.booleanValue(), &err));
            break;
        break;
        default:  // Should never happen
            _hidl_cb(result(ResultCode::INVALID_DATA, "Invalid data entry."), encryptedVal);
            return Void();
        break;
    }
    // END Data entry

    if (cmdData.get() == nullptr || err.err != CN_CBOR_NO_ERROR) {
        _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization."), encryptedVal);
        return Void();
    }

    if (mCurrentValueDirectlyAvailable) {
        p1 |= 0x80;  // Bit 8 indicates if this is a directly available entry
    }

    std::vector<uint8_t> buffer = encodeCborAsVector(cmdData.get(), &err);

    if (stringSize != -1) {
        if (stringSize != mCurrentValueEntrySize) {  // Chunking
            p1 |= 0x4;                               // Bit 3 indicates chunking
            
            if (mCurrentValueEncryptedContent == 0) {
                // First chunk, need to encode the full length at the beginning
                auto entrySize = CBORPtr(cn_cbor_int_create(mCurrentValueEntrySize, &err));
                std::vector<uint8_t> encodedEntrySize = encodeCborAsVector(entrySize.get(), &err);

                // Major type from data buffer
                encodedEntrySize[0] &= 0x1F;
                encodedEntrySize[0] |= buffer[0] & 0xE0;

                // Copy type and length to buffer
                if (encodedEntrySize.size() + stringSize > buffer.size()) {
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
            _hidl_cb(result(ResultCode::FAILED, "Entry value is exceeding the defined entry size"),
                     encryptedVal);
            return Void();
        } else if (mCurrentValueEncryptedContent != mCurrentValueEntrySize &&
                   stringSize != mAppletConnection.chunkSize()) {
            _hidl_cb(result(ResultCode::FAILED, "Entry size does not match chunk size"),
                     encryptedVal);
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
        _hidl_cb(swToErrorMessage(response, "Error personalizing attribute"), encryptedVal);
        return Void();
    }

    encryptedVal.resize(response.dataSize());

    std::copy(response.dataBegin(), response.dataEnd(), encryptedVal.begin());

    if (stringSize == -1 || mCurrentValueEncryptedContent == mCurrentValueEntrySize) {
        // Finish this entry
        mCurrentNamespaceEntryCount--;
    }

    _hidl_cb(resultOk(), encryptedVal);
    return Void();
}

Return<void> WritableIdentityCredential::finishAddingEntries(finishAddingEntries_cb _hidl_cb) {
    hidl_vec<uint8_t> signature;

    if (!verifyAppletPersonalizationStatus()) {
        _hidl_cb(result(ResultCode::FAILED, "Personalization not started yet. "), signature, signature);
        return Void();
    }

    // Check if this was the last entry in the last namespace
    if (mCurrentNamespaceEntryCount != 0 || mCurrentNamespaceId != mNamespaceEntries.size()) {
        _hidl_cb(result(ResultCode::FAILED,
                        "Missing entries to personalize. Personalized %d of %d entries.",
                        mNamespaceEntries[mCurrentNamespaceId] - mCurrentNamespaceEntryCount,
                        mNamespaceEntries[mCurrentNamespaceId]),
                 signature, signature);
        return Void();
    }

    // Retrieve signedData
    CommandApdu signDataCmd{kCLAProprietary, kINSSignPersonalizedData, 0, 0};

    ResponseApdu signResponse = mAppletConnection.transmit(signDataCmd);
    if (!signResponse.ok() || signResponse.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(signResponse, "Signature creation failed"), signature, signature);
        // Personalization failed
        mPersonalizationStarted = false;
        mAppletConnection.close();
        return Void();
    }

    // Success, prepare return data

    // Combine credential information into CBOR credentialData structure
    cn_cbor_errback err;
    cn_cbor* credentialData = cn_cbor_array_create(&err);
    std::vector<uint8_t> resultCredData;

    if (!cn_cbor_array_append(credentialData, cn_cbor_string_create(mDocType.c_str(), &err), &err) ||
        !cn_cbor_array_append(credentialData, encodeCborBoolean(mIsTestCredential, &err), &err) ||
        !cn_cbor_array_append(credentialData, cn_cbor_data_create(mCredentialBlob.data(), 
                            mCredentialBlob.size(), &err), &err)) {
        _hidl_cb(result(ResultCode::FAILED, "Error encoding credentialData as CBOR structure. "),
                 resultCredData, signature);
        return Void();
    }

    // Return values
    signature.resize(signResponse.dataSize());
    std::copy(signResponse.dataBegin(), signResponse.dataEnd(), signature.begin());

    resultCredData = encodeCborAsVector(credentialData, &err);

    if (err.err == CN_CBOR_NO_ERROR) {
        _hidl_cb(resultOk(), resultCredData, signature);
    } else {
        _hidl_cb(result(ResultCode::FAILED, "Error encoding credentialData as CBOR structure. "),
                 resultCredData, signature);
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
