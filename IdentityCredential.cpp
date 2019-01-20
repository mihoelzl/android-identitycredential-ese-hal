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

#include <cn-cbor/cn-cbor.h>

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

using ::android::hardware::keymaster::capability::V1_0::KeymasterCapability;

static constexpr uint8_t kCLAProprietary = 0x80;
static constexpr uint8_t kINSLoadCredential = 0x30;
static constexpr uint8_t kINSLoadEphemeralKey = 0x52;
static constexpr uint8_t kINSAuthenticate = 0x31;
static constexpr uint8_t kINSLoadAccessControlProfile = 0x32;
static constexpr uint8_t kINSGetNamespace = 0x3A;
static constexpr uint8_t kINSGetEntry = 0x3B;
static constexpr uint8_t kINSCreateSignature = 0x3C;
static constexpr uint8_t kINSCreateSigningKey = 0x40;

static constexpr uint8_t kDigestSize = 32;

IdentityCredential::~IdentityCredential(){
    mAppletConnection.close();
}

ResultCode IdentityCredential::initializeCredential(const hidl_vec<uint8_t>& credentialBlob){

    if (!mAppletConnection.connectToSEService()) {
        ALOGE("Error while trying to connect to SE service");
        return ResultCode::IOERROR;
    }
   
    cn_cbor_errback err;
    unsigned char encoded[1024];
    ssize_t enc_sz;

    cn_cbor *cb_data = cn_cbor_data_create(credentialBlob.data(), credentialBlob.size(), &err);
    if(err.err != CN_CBOR_NO_ERROR){
        ALOGE("Error parsing credential blob");
        return ResultCode::INVALID_DATA;
    }
    enc_sz = cn_cbor_encoder_write(encoded, 0, sizeof(encoded), cb_data);
    mCredentialBlob.assign(&encoded[0], &encoded[enc_sz]);

    cn_cbor_free(cb_data);

    ALOGD("Successfully initialized");

    return ResultCode::OK;
}

void IdentityCredential::resetRetrievalState() {
    mCurrentNamespaceEntryCount = 0;
    mCurrentNamespaceId = 0;

    mCurrentValueDecryptedContent = 0;
    mCurrentValueEntrySize = 0;

    mRetrievalStarted = false;
}

bool IdentityCredential::verifyAppletRetrievalStarted() {
    if (!mAppletConnection.isChannelOpen()) {
        ALOGE("No connection to applet");
        return false;
    }
    if(!mRetrievalStarted){
        ALOGE("Retrieval not started yet");
        return false;
    }
    return true;
}

ResultCode IdentityCredential::loadCredential(){
    // Send the command to the applet to load the applet
    CommandApdu command{kCLAProprietary, kINSLoadCredential, 0, 0, mCredentialBlob.size(), 0};
    std::copy(mCredentialBlob.begin(), mCredentialBlob.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);
    return swToErrorMessage(response);
}

ResultCode IdentityCredential::loadEphemeralKey() {
    CommandApdu command{kCLAProprietary, kINSLoadEphemeralKey, 0x80, 0, mLoadedEphemeralKey.size(), 0};
    std::copy(mLoadedEphemeralKey.begin(), mLoadedEphemeralKey.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);
    return swToErrorMessage(response);
}


Return<void> IdentityCredential::deleteCredential(deleteCredential_cb /*_hidl_cb*/) {
    // TODO
    return Void();
}

Return<void> IdentityCredential::createEphemeralKeyPair(
    ::android::hardware::identity_credential::V1_0::KeyType keyType,
    createEphemeralKeyPair_cb _hidl_cb) {
    hidl_vec<uint8_t> ephKey;

    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(ephKey);
            return Void();
        }
    }

    ResultCode result = loadCredential();
    if(result != ResultCode::OK){
        _hidl_cb(ephKey);
        return Void();
    }

    uint8_t p2 = 0;

    if (keyType != KeyType::EC_NIST_P_256) {
        _hidl_cb(ephKey);
        return Void();
    } else {
        p2 = 1;
    }

    CommandApdu command{kCLAProprietary, kINSLoadEphemeralKey, 0, p2};
    ResponseApdu response = mAppletConnection.transmit(command);

    // Check response
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        ALOGE("Error loading credential SW(%x)", response.status());
        _hidl_cb(ephKey);
    }

    unsigned long long arraySize = 0;
    std::string resultEphPubKey;
    std::string resultEphPriKey;
    std::string mac;

    auto begin = response.dataBegin();
    auto end = response.dataEnd();

    auto len = CborLite::decodeArraySize(begin, end, arraySize);
    if (len == CborLite::INVALIDDATA) {
        ALOGE("Received data structure invalid");
        _hidl_cb(ephKey);
        return Void();
    }

    if (CborLite::decodeBytes(begin, end, resultEphPubKey) == CborLite::INVALIDDATA ||
        CborLite::decodeBytes(begin, end, resultEphPriKey) == CborLite::INVALIDDATA ||
        CborLite::decodeBytes(begin, end, mac) == CborLite::INVALIDDATA) {
        ALOGE("Received data structure invalid");
        _hidl_cb(ephKey);
        return Void();
    }
    mLoadedEphemeralKey.clear();

    CborLite::encodeArraySize(mLoadedEphemeralKey, 2ul);
    CborLite::encodeBytes(mLoadedEphemeralKey, resultEphPubKey);
    CborLite::encodeBytes(mLoadedEphemeralKey, mac);

    ephKey.resize(resultEphPriKey.size());

    std::copy(resultEphPriKey.begin(), resultEphPriKey.end(), ephKey.begin());
    _hidl_cb(ephKey);
    
    return Void();
}

ResultCode IdentityCredential::authenticateReader(hidl_vec<uint8_t> readerAuthenticationData,
                                                  hidl_vec<uint8_t> readerAuthPubKey,
                                                  hidl_vec<uint8_t> readerSignature) {
    uint8_t p2 = 0;
    cn_cbor_errback err;

    cn_cbor* commandData = cn_cbor_array_create(&err);
    cn_cbor_array_append(commandData,
                         cn_cbor_data_create(readerAuthenticationData.data(),
                                             readerAuthenticationData.size(), &err),
                         &err);

    if (err.err != CN_CBOR_NO_ERROR) {
        cn_cbor_free(commandData);
        return ResultCode::INVALID_DATA;
    }

    if (readerAuthPubKey.size() != 0 && readerSignature.size() != 0) {
        // Authenticate reader
        p2 = 1;

        cn_cbor_array_append(commandData,
                cn_cbor_data_create(readerAuthPubKey.data(), readerAuthPubKey.size(), &err), &err);
        if (err.err == CN_CBOR_NO_ERROR) {
            cn_cbor_array_append(commandData, cn_cbor_data_create(readerSignature.data(),
                                 readerSignature.size(), &err), &err);
        }
        if (err.err != CN_CBOR_NO_ERROR) {
            cn_cbor_free(commandData);
            return ResultCode::INVALID_DATA;
        }
    } else {
        // No reader authentication, only send readerAuthenticationData
        p2 = 0;
    }

    CommandApdu command = createCommandApduFromCbor(kINSAuthenticate, 0, p2, commandData, &err);
    if(err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        cn_cbor_free(commandData);
        return ResultCode::INVALID_DATA;
    }

    ResponseApdu response = mAppletConnection.transmit(command);
    
    cn_cbor_free(commandData);
    return swToErrorMessage(response);
}

ResultCode IdentityCredential::authenticateUser(KeymasterCapability authToken) {
    uint8_t p2 = 2;
    cn_cbor_errback err;

    cn_cbor* commandData = cn_cbor_array_create(&err);

    // TODO(hoelzl) Do we need to add more for authentication?
    if (!cn_cbor_array_append(commandData, cn_cbor_int_create(authToken.challenge, &err), &err) ||
        !cn_cbor_array_append(commandData, cn_cbor_int_create(authToken.timestamp, &err), &err) ||
        !cn_cbor_array_append(commandData, cn_cbor_data_create(authToken.secure_token.data(),
                                                  authToken.secure_token.size(), &err), &err)) {
        cn_cbor_free(commandData);
        return ResultCode::INVALID_DATA;
    }

    CommandApdu command = createCommandApduFromCbor(kINSAuthenticate, 0, p2, commandData, &err);
    if(err.err != CN_CBOR_NO_ERROR) {
        cn_cbor_free(commandData);
        return ResultCode::INVALID_DATA;
    }

    ResponseApdu response = mAppletConnection.transmit(command);
    
    cn_cbor_free(commandData);
    return swToErrorMessage(response);
}

Return<ResultCode> IdentityCredential::startRetrieval(const StartRetrievalArguments& args){
    hidl_vec<uint8_t> readerAuthPubKey(0);

    // Check the incoming data
    // Get the reader pub key from the secure access control profile (only one profile should have it)
    for (auto& profile : args.accessControlProfiles) {
        if(profile.readerAuthPubKey.size() != 0) {
            if (readerAuthPubKey.size() != 0 && readerAuthPubKey != profile.readerAuthPubKey) {
                ALOGE("More than one profile with different reader auth pub key specified. Aborting!");
                return ResultCode::INVALID_DATA;
            }
            readerAuthPubKey = profile.readerAuthPubKey;
        }
    }
    // Initiate communication to applet 
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            return swToErrorMessage(selectResponse);
        }
    }

    resetRetrievalState();

    // Load the credential blob and the ephemeral keys (if it has been initialized)
    ResultCode result = loadCredential();
    if (result != ResultCode::OK) {
        return result;
    }
    // Make sure that the ephemeral key for this identity credential is loaded
    if (mLoadedEphemeralKey.size() != 0) {
        result = loadEphemeralKey();
        if (result != ResultCode::OK) {
            return result;
        }
    }

    // Authenticate reader. If pubkey or signature is empty, only the session transcript will be
    // sent to the applet
    ResultCode authResult =
            authenticateReader(args.requestData, readerAuthPubKey, args.readerSignature);
    if (authResult != ResultCode::OK) {
        ALOGE("Reader authentication failed");
        return authResult;
    }
    // Authenticate the user with the keymastercapability token
    authResult = authenticateUser(args.authToken);
    if (authResult != ResultCode::OK) {
        ALOGE("User authentication failed");
        return authResult;
    }
    // DONE with authentication

    cn_cbor_errback err;
    // Load secure access control profiles onto the applet
    for (auto& profile : args.accessControlProfiles) {
        bool success = false;
        cn_cbor* commandData = cn_cbor_array_create(&err);
        if(err.err != CN_CBOR_NO_ERROR){
            ALOGE("Error initializing cbor object");
            continue;
        }

        cn_cbor* acp = encodeCborAccessControlProfile(profile.id, profile.readerAuthPubKey,
                                                      profile.capabilityId, profile.capabilityType, 
                                                      profile.timeout);

        // Append Access Control profile and MAC
        if (acp != nullptr && cn_cbor_array_append(commandData, acp, &err)) {
            if (cn_cbor_array_append(
                        commandData,
                        cn_cbor_data_create(profile.mac.data(), profile.mac.size(), &err), &err)) {
                // Send command
                CommandApdu command =
                        createCommandApduFromCbor(kINSLoadAccessControlProfile, 0, 0, commandData, &err);

                if(err.err == CN_CBOR_NO_ERROR) {
                    ResponseApdu response = mAppletConnection.transmit(command);
                    if (response.ok() && response.status() == AppletConnection::SW_OK) {
                        // Success
                        success = true;
                    } 
                } 
            }
        } else if (acp != nullptr) {
            cn_cbor_free(acp);
        }

        if(!success) {
            ALOGE("Could not initialize access control profile");
        }
        cn_cbor_free(commandData);
    }
    // DONE loading access control profiles

    // Save the request counts for later retrieval
    mNamespaceRequestCounts = args.requestCounts;
    mRetrievalStarted = true;
    mRequestDataDigest = sha256(args.requestData);

    return ResultCode::OK;
}

Return<ResultCode> IdentityCredential::startRetrieveEntryValue(
        const hidl_string& nameSpace, const hidl_string&  name, uint32_t entrySize,
        const hidl_vec<uint8_t>& accessControlProfileIds) {

    uint8_t p1 = 0; 
    uint8_t p2 = 0; 
    cn_cbor_errback err;

    if (!verifyAppletRetrievalStarted()) {
        ALOGE("Entry retrieval not started yet");
        return ResultCode::FAILED;
    } else if (mCurrentNamespaceEntryCount == 0 &&
               mNamespaceRequestCounts.size() == mCurrentNamespaceId) {
        ALOGE("All entries have already been retrieved.");
        return ResultCode::FAILED;
    }

    if(mCurrentNamespaceEntryCount == 0) {

        mCurrentNamespaceEntryCount = mNamespaceRequestCounts[mCurrentNamespaceId];

        cn_cbor* commandData =
                encodeCborNamespaceConf(nameSpace, mCurrentNamespaceEntryCount);
        if(commandData == nullptr){
           return ResultCode::INVALID_DATA;
        }

        // Set the number of namespaces in p1p2
        p1 = (mNamespaceRequestCounts.size() >> 8) & 0x3F;
        p2 = mNamespaceRequestCounts.size() & 0xFF;
    
        CommandApdu command = createCommandApduFromCbor(kINSGetNamespace, p1, p2, commandData, &err); 
        
        if(err.err != CN_CBOR_NO_ERROR) {
            cn_cbor_free(commandData);
            return ResultCode::INVALID_DATA;
        }

        ResponseApdu response = mAppletConnection.transmit(command);
        cn_cbor_free(commandData);

        if(response.ok() && response.status() == AppletConnection::SW_OK){
            mCurrentNamespaceId++;

            ALOGD("New namespace retrieval started");
        } else {
            ALOGE("Error during namespace initialization");
            return swToErrorMessage(response);
        }
    }

    p1 = 0;
    p2 = 0;

    // Encode the additional data and send it to the applet
    cn_cbor* commandData = encodeCborAdditionalData(nameSpace, name, accessControlProfileIds);

    if (commandData == nullptr) {
        ALOGE("Error initializing CBOR");
        return ResultCode::INVALID_DATA;
    }

    CommandApdu command = createCommandApduFromCbor(kINSGetEntry, p1, p2, commandData, &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        cn_cbor_free(commandData);
        ALOGE("Error initializing CBOR");
        return ResultCode::INVALID_DATA;
    }

    ResponseApdu response = mAppletConnection.transmit(command);
    
    mCurrentValueEntrySize = entrySize;
    mCurrentValueDecryptedContent = 0;

    cn_cbor_free(commandData);
    return swToErrorMessage(response);
}

Return<void> IdentityCredential::retrieveEntryValue(const hidl_vec<uint8_t>& encryptedContent,
                                                    retrieveEntryValue_cb _hidl_cb) {
    EntryValue result;
    uint8_t p1 = 0;  
    uint8_t p2 = 0; 
    cn_cbor_errback err;
    bool isLastChunk = false;
    bool firstChunk = false;

    if (!verifyAppletRetrievalStarted()) {
        ALOGE("Entry retrieval not started yet");
        _hidl_cb(ResultCode::FAILED, result);
        return Void();
    }

    if (mCurrentValueDecryptedContent != 0 ||
        mCurrentValueEntrySize > mAppletConnection.chunkSize()) {  // Chunking
        p1 |= 0x4;                                               // Bit 3 indicates chunking
        if (mCurrentValueDecryptedContent != 0) {
            p1 |= 0x2;  // Bit 2 indicates a chunk "inbetween"
        } else {
            firstChunk = true;
        }

        // Check if this is the last chunk. Note: we actually do not know the size of the decrypted
        // content (size of the CBOR header was added by HAL). Issue at corner case where entry +
        // CBOR header size exceeds chunk. To be safe, check with maximum CBOR header size of 9
        if (mCurrentValueDecryptedContent + encryptedContent.size() - 9 >= mCurrentValueEntrySize) {
            p1 |= 0x1;
            isLastChunk = true;
        }
    } else {
        isLastChunk = true;
        p1 = 0x1; // Indicates that this is the only value in chain
    }

    CommandApdu command{kCLAProprietary, kINSGetEntry, p1, p2, encryptedContent.size(), 0};  
    std::copy(encryptedContent.begin(), encryptedContent.end(), command.dataBegin());  
            
    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response), result);
        return Void();
    }

    // Decode the decrypted content and return
    cn_cbor *entryVal;

    if (firstChunk) {
            //TODO, handle first chunk with different length field
    }

    entryVal = cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err);
    if (entryVal == nullptr) {
        _hidl_cb(ResultCode::INVALID_DATA, result);
        return Void();
    }

    // Check the data type
    int64_t entrySize = -1;
    std::vector<uint8_t> dataBytes;
    switch (entryVal->type) {
        case CN_CBOR_BYTES:
            entrySize = entryVal->length;
            mCurrentValueDecryptedContent += entrySize;
            dataBytes.assign(entryVal->v.bytes, entryVal->v.bytes + entrySize);
            result.byteString(dataBytes);
            break;
        case CN_CBOR_TEXT:
            entrySize = entryVal->length;
            mCurrentValueDecryptedContent += entrySize;
            result.textString(hidl_string(entryVal->v.str, entrySize));
            break;
        case CN_CBOR_INT:
            result.integer(entryVal->v.sint);
            break;
        case CN_CBOR_UINT:
            result.integer(entryVal->v.uint);
            break;
        case CN_CBOR_TRUE:
            result.booleanValue(true);
            break;
        case CN_CBOR_FALSE:
            result.booleanValue(false);
            break;
        default:
            _hidl_cb(ResultCode::INVALID_DATA, result);
            return Void();
    }

    cn_cbor_free(entryVal);
    
    ALOGD("Entry retrieved. Expected  %u", mCurrentValueEntrySize);
    if (entrySize == -1 || mCurrentValueDecryptedContent == mCurrentValueEntrySize) {
        // Finish this entry
        mCurrentNamespaceEntryCount--;

        if (!isLastChunk) {  // The estimate at the beginning was wrong: send final command to applet
            ALOGD("Entry not finished, sending final command");

            p1 |= 0x1;
            CommandApdu command{kCLAProprietary, kINSGetEntry, p1, p2};                     
            ResponseApdu response = mAppletConnection.transmit(command);

            if (!response.ok() || response.status() != AppletConnection::SW_OK) {
                _hidl_cb(swToErrorMessage(response), result);
                return Void();
            }
        }
    }
    
    _hidl_cb(ResultCode::OK, result);
    return Void();
}

Return<void> IdentityCredential::finishRetrieval(
        const hidl_vec<uint8_t>& signingKeyBlob,
        const hidl_vec<uint8_t>& prevAuditSignatureHash, finishRetrieval_cb _hidl_cb) {
            
    AuditLogEntry auditLog;
    cn_cbor_errback err;
    hidl_vec<uint8_t> signature;

    if (!verifyAppletRetrievalStarted()) {
        ALOGE("Entry retrieval not started yet.");
        _hidl_cb(ResultCode::FAILED, signature, auditLog);
        return Void();
    } else if (mCurrentNamespaceEntryCount != 0 ||
               mNamespaceRequestCounts.size() != mCurrentNamespaceId) {
        ALOGE("Entry retrieval not finished yet.");
        _hidl_cb(ResultCode::FAILED, signature, auditLog);
        return Void();
    }

    cn_cbor* commandData = cn_cbor_array_create(&err);

    if (commandData == nullptr) {
        _hidl_cb(ResultCode::FAILED, signature, auditLog);
        return Void();
    }

    if (mRequestDataDigest.size() != kDigestSize) {
        ALOGE("Entry retrieval not successfully initialized. Mising request data digest.");
        _hidl_cb(ResultCode::INVALID_DATA, signature, auditLog);
        return Void();
    }

        ALOGE("DATA SIZE %zu.", prevAuditSignatureHash.size());
    if (!cn_cbor_array_append(commandData, cn_cbor_data_create(prevAuditSignatureHash.data(),
                              prevAuditSignatureHash.size(), &err), &err) ||
        !cn_cbor_array_append(commandData, cn_cbor_data_create(signingKeyBlob.data(), 
                              signingKeyBlob.size(), &err), &err)) {
        cn_cbor_free(commandData);

        ALOGE("Error encoding the provided data.");
        _hidl_cb(ResultCode::INVALID_DATA, signature, auditLog);
        return Void();
    }
    
    CommandApdu command = createCommandApduFromCbor(kINSCreateSignature, 0, 0, commandData, &err);
    if(err.err != CN_CBOR_NO_ERROR) {
        ALOGE("Error initializing CBOR object. ");
        cn_cbor_free(commandData);
        _hidl_cb(ResultCode::INVALID_DATA, signature, auditLog);
        return Void();
    }
    cn_cbor_free(commandData);

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        ALOGE("Signature creation failed.");
        _hidl_cb(swToErrorMessage(response), signature, auditLog);
        return Void();
    }

    cn_cbor *cb_main;

    cb_main = cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err);
    if (cb_main == nullptr) {
        _hidl_cb(swToErrorMessage(response), signature, auditLog);
        return Void();
    }

    cn_cbor *cbor_auditSignature = cn_cbor_index(cb_main, 0);
    cn_cbor *cbor_responseHash = cn_cbor_index(cb_main, 1);
    cn_cbor *cbor_responseSignature = cn_cbor_index(cb_main, 2);

    if (cbor_auditSignature == nullptr || cbor_responseHash == nullptr ||
        cbor_responseSignature == nullptr || cbor_auditSignature->type != CN_CBOR_BYTES ||
        cbor_responseHash->type != CN_CBOR_BYTES || cbor_responseSignature->type != CN_CBOR_BYTES ||
        cbor_auditSignature->v.bytes == nullptr || cbor_responseHash->v.bytes == nullptr ||
        cbor_responseSignature->v.bytes == nullptr || cbor_responseHash->length != kDigestSize) {
            
        ALOGE("Error decoding SE response.");
        cn_cbor_free(cb_main);

        _hidl_cb(ResultCode::INVALID_DATA, signature, auditLog);
        return Void();
    }

    auditLog.signature.resize(cbor_auditSignature->length);
    signature.resize(cbor_responseSignature->length);

    std::copy(mRequestDataDigest.begin(), mRequestDataDigest.end(), auditLog.requestHash.data());
    std::copy(cbor_responseHash->v.bytes, cbor_responseHash->v.bytes + cbor_responseHash->length,
              auditLog.responseHash.data());
    std::copy(cbor_auditSignature->v.bytes,
              cbor_auditSignature->v.bytes + cbor_auditSignature->length,
              auditLog.signature.data());
    std::copy(cbor_responseSignature->v.bytes,
              cbor_responseSignature->v.bytes + cbor_responseSignature->length, signature.begin());

    cn_cbor_free(cb_main);

    _hidl_cb(ResultCode::OK, signature, auditLog);

    return Void();
}

Return<void> IdentityCredential::generateSigningKeyPair(
    ::android::hardware::identity_credential::V1_0::KeyType keyType,
    generateSigningKeyPair_cb _hidl_cb) {
    hidl_vec<uint8_t> signingKeyCertificate(0);
    hidl_vec<uint8_t> signingKeyBlob(0);

    // Initiate communication to applet 
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(swToErrorMessage(selectResponse), signingKeyBlob, signingKeyCertificate);
            return Void();
        }
    }

    // Load the credential blob and the ephemeral keys (if it has been initialized)
    ResultCode result = loadCredential();
    if (result != ResultCode::OK) {
        ALOGE("Cannot load credential");
        _hidl_cb(result, signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    uint8_t p2 = 0;

    if (keyType != KeyType::EC_NIST_P_256) {
        ALOGE("Elliptic curve not supported");
        _hidl_cb(result, signingKeyBlob, signingKeyCertificate);
        return Void();
    } else {
        p2 = 1;
    }

    cn_cbor *cb_main;
    cn_cbor_errback err;

    // Create a signing key pair and return the result
    CommandApdu command{kCLAProprietary, kINSCreateSigningKey, 0, p2};
    ResponseApdu response = mAppletConnection.transmit(command);
    
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response), signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    cb_main = cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err);
    if (cb_main == nullptr) {
        _hidl_cb(swToErrorMessage(response), signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    cn_cbor *cbor_signKeyBlob = cn_cbor_index(cb_main, 0);
    cn_cbor *cbor_signingKeyCert = cn_cbor_index(cb_main, 1);

    if (cbor_signKeyBlob == nullptr || cbor_signingKeyCert == nullptr ||
        cbor_signKeyBlob->type != CN_CBOR_BYTES || cbor_signingKeyCert->type != CN_CBOR_BYTES ||
        cbor_signKeyBlob->v.bytes == nullptr || cbor_signingKeyCert->v.bytes == nullptr) {
        ALOGE("Error decoding SE response");
        cn_cbor_free(cb_main);

        _hidl_cb(ResultCode::INVALID_DATA, signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    signingKeyBlob.resize(cbor_signKeyBlob->length);
    signingKeyCertificate.resize(cbor_signingKeyCert->length);

    std::copy(cbor_signKeyBlob->v.bytes, cbor_signKeyBlob->v.bytes + cbor_signKeyBlob->length,
              signingKeyBlob.begin());
    std::copy(cbor_signingKeyCert->v.bytes, cbor_signingKeyCert->v.bytes + cbor_signingKeyCert->length,
              signingKeyCertificate.begin());

    _hidl_cb(ResultCode::OK, signingKeyBlob, signingKeyCertificate);
    cn_cbor_free(cb_main);
    
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
