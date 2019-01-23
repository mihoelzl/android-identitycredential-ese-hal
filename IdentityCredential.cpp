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

ResultCode IdentityCredential::initializeCredential(const hidl_vec<uint8_t>& credentialData){

    if (!mAppletConnection.connectToSEService()) {
        ALOGE("Error while trying to connect to SE service");
        return ResultCode::IOERROR;
    }
   
    mCredentialBlob = credentialData;
    
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

Return<void> IdentityCredential::createEphemeralKeyPair(KeyType keyType,
                                                        createEphemeralKeyPair_cb _hidl_cb) {
    hidl_vec<uint8_t> emptyEphKey;
    uint8_t p1 = 0;
    uint8_t p2 = 0;

    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            ALOGE("[%s] : Could not select the applet. ", __func__);
            _hidl_cb(emptyEphKey);
            return Void();
        }
    }

    ResultCode result = loadCredential();
    if(result != ResultCode::OK){
        ALOGE("[%s] : Error loading the credential. ", __func__);
        _hidl_cb(emptyEphKey);
        return Void();
    }

    if (keyType != KeyType::EC_NIST_P_256) {
        ALOGE("[%s] : Elliptic curve not supported.", __func__);
        _hidl_cb(emptyEphKey);
        return Void();
    } else {
        p2 = 1;
    }

    CommandApdu command{kCLAProprietary, kINSLoadEphemeralKey, p1, p2};
    ResponseApdu response = mAppletConnection.transmit(command);

    // Check response
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        ALOGE("Error loading credential SW(%x)", response.status());
        _hidl_cb(emptyEphKey);
        return Void();
    }

    // Decode the ephemeral keypair and the mac
    cn_cbor_errback err;
    auto cborResponse = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));

    if (cborResponse.get() == nullptr) {
        ALOGE("[%s] : Error decoding SE response.", __func__);
        _hidl_cb(emptyEphKey);
        return Void();
    }

    cn_cbor *cb_ephPubKey = cn_cbor_index(cborResponse.get(), 0);
    cn_cbor *cb_ephPrivKey = cn_cbor_index(cborResponse.get(), 1);
    cn_cbor *cb_pkMac = cn_cbor_index(cborResponse.get(), 2);

    if (cb_ephPubKey == nullptr || cb_ephPrivKey == nullptr || cb_pkMac == nullptr ||
        cb_ephPubKey->type != CN_CBOR_BYTES || cb_ephPrivKey->type != CN_CBOR_BYTES ||
        cb_pkMac->type != CN_CBOR_BYTES || cb_ephPubKey->v.bytes == nullptr ||
        cb_ephPrivKey->v.bytes == nullptr || cb_pkMac->v.bytes == nullptr) {

        ALOGE("[%s] : Error decoding SE response.", __func__);

        _hidl_cb(emptyEphKey);
        return Void();
    }

    // Save the ephemeral key and the MAC as cbor structure (see loadEphemeralKey)
    auto cborStructureemptyEphKey = CBORPtr(cn_cbor_array_create(&err));
    if (cborStructureemptyEphKey.get() == nullptr) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);

        _hidl_cb(emptyEphKey);
        return Void();
    }
    if (!cn_cbor_array_append(cborStructureemptyEphKey.get(),
                              cn_cbor_data_create(cb_ephPubKey->v.bytes, cb_ephPubKey->length, &err),
                              &err) ||
        !cn_cbor_array_append(cborStructureemptyEphKey.get(),
                              cn_cbor_data_create(cb_pkMac->v.bytes, cb_pkMac->length, &err),
                              &err)) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        _hidl_cb(emptyEphKey);
        return Void();
    }
    
    mLoadedEphemeralKey = encodeCborAsVector(cborStructureemptyEphKey.get(), &err);

    // Parse received data as ec private key
    hidl_vec<uint8_t> ephKey = encodeECPrivateKey(cb_ephPrivKey, &err);

    if(err.err != CN_CBOR_NO_ERROR){
        ALOGE("[%s] : Error generating private key.", __func__);
        _hidl_cb(emptyEphKey);
        return Void();
    }

    _hidl_cb(ephKey);

    return Void();
}

ResultCode IdentityCredential::authenticateReader(const hidl_vec<uint8_t>& readerAuthData,
                                                  const hidl_vec<uint8_t>& readerPubKey,
                                                  const hidl_vec<uint8_t>& signature) {
    uint8_t p2 = 0;
    cn_cbor_errback err;

    auto cmdData = CBORPtr(cn_cbor_array_create(&err));
    if(cmdData.get() == nullptr){
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    cn_cbor_array_append(cmdData.get(),
                         cn_cbor_data_create(readerAuthData.data(),
                                             readerAuthData.size(), &err),
                         &err);

    if (err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    if (readerPubKey.size() != 0 && signature.size() != 0) {
        // Authenticate reader
        p2 = 1;

        if (!cn_cbor_array_append(cmdData.get(), 
                    cn_cbor_data_create(readerPubKey.data(), readerPubKey.size(), &err), &err) ||
            !cn_cbor_array_append(cmdData.get(), 
                    cn_cbor_data_create(signature.data(), signature.size(), &err), &err)) {
            ALOGE("[%s] : Error in CBOR initalization. ", __func__);
            return ResultCode::INVALID_DATA;
        }
    } else {
        // No reader authentication, only send readerAuthData
        p2 = 0;
    }

    CommandApdu command = createCommandApduFromCbor(kINSAuthenticate, 0, p2, cmdData.get(), &err);
    if(err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    ResponseApdu response = mAppletConnection.transmit(command);
    
    return swToErrorMessage(response);
}

ResultCode IdentityCredential::authenticateUser(const KeymasterCapability& authToken) {
    uint8_t p2 = 2;
    cn_cbor_errback err;

    auto cmdData = CBORPtr(cn_cbor_array_create(&err));

    if(cmdData.get() == nullptr){
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    // TODO(hoelzl) Do we need to add more for authentication?
    if (!cn_cbor_array_append(cmdData.get(), cn_cbor_int_create(authToken.challenge, &err), &err) ||
        !cn_cbor_array_append(cmdData.get(), cn_cbor_int_create(authToken.timestamp, &err), &err) ||
        !cn_cbor_array_append(cmdData.get(), cn_cbor_data_create(authToken.secure_token.data(),
                                                  authToken.secure_token.size(), &err), &err)) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    CommandApdu command = createCommandApduFromCbor(kINSAuthenticate, 0, p2, cmdData.get(), &err);
    if(err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error in CBOR initalization. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    ResponseApdu response = mAppletConnection.transmit(command);
    
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
            readerAuthPubKey = getECPublicKeyFromCertificate(profile.readerAuthPubKey);

            if (readerAuthPubKey.size() == 0) {
                ALOGE("[%s] : Certificate parsing error.", __func__);
                return ResultCode::INVALID_DATA;
            }
        }
    }
    // Initiate communication to applet 
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            ALOGE("[%s] : Could not select the applet. ", __func__);
            return swToErrorMessage(selectResponse);
        }
    }

    resetRetrievalState();

    // Load the credential blob and the ephemeral keys (if it has been initialized)
    ResultCode result = loadCredential();
    if (result != ResultCode::OK) {
        ALOGE("[%s] : Error loading the credential. ", __func__);
        return result;
    }
    // Make sure that the ephemeral key for this identity credential is loaded
    if (mLoadedEphemeralKey.size() != 0) {
        result = loadEphemeralKey();
        if (result != ResultCode::OK) {
            ALOGE("[%s] : Error loading the ephemeral key to the applet. ", __func__);
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

    // TODO: sort secureAccessControlProfile ascending by ID

    cn_cbor_errback err;
    // Load secure access control profiles onto the applet
    for (auto& profile : args.accessControlProfiles) {
        auto commandData = CBORPtr(cn_cbor_array_create(&err));
        if(commandData.get() == nullptr){
            ALOGE("[%s] : Error in CBOR initalization. ", __func__);
            return ResultCode::INVALID_DATA;
        }

        cn_cbor* acp = encodeCborAccessControlProfile(
                profile.id, getECPublicKeyFromCertificate(profile.readerAuthPubKey),
                profile.capabilityId, profile.capabilityType, profile.timeout);

        // Append Access Control profile and MAC
        if (acp == nullptr || !cn_cbor_array_append(commandData.get(), acp, &err)){
            ALOGE("[%s] : Error in CBOR initalization. ", __func__);
            cn_cbor_free(acp);
            return ResultCode::INVALID_DATA;
        }

        if (!cn_cbor_array_append(commandData.get(),
                                  cn_cbor_data_create(profile.mac.data(), profile.mac.size(), &err),
                                  &err)) {
            ALOGE("[%s] : Error adding MAC to CBOR structure. ", __func__);
            return ResultCode::INVALID_DATA;
        }

        // Send command
        CommandApdu command =
                createCommandApduFromCbor(kINSLoadAccessControlProfile, 0, 0, commandData.get(), &err);

        if (err.err != CN_CBOR_NO_ERROR) {
            return ResultCode::FAILED;
        }

        ResponseApdu response = mAppletConnection.transmit(command);

        if (!response.ok() || response.status() != AppletConnection::SW_OK) {
            // Access control profile initialization failed, abort
            return swToErrorMessage(response);
        }
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
        ALOGE("[%s] : Entry retrieval not started yet. ", __func__);
        return ResultCode::FAILED;
    } else if (mCurrentNamespaceEntryCount == 0 &&
               mNamespaceRequestCounts.size() == mCurrentNamespaceId) {
        ALOGE("[%s] : All entries have already been retrieved. ", __func__);
        return ResultCode::FAILED;
    }

    if(mCurrentNamespaceEntryCount == 0) {
        mCurrentNamespaceEntryCount = mNamespaceRequestCounts[mCurrentNamespaceId];

        auto commandData = CBORPtr(encodeCborNamespaceConf(nameSpace, mCurrentNamespaceEntryCount));
        if(commandData.get() == nullptr){
           return ResultCode::INVALID_DATA;
        }

        // Set the number of namespaces in p1p2
        p1 = (mNamespaceRequestCounts.size() >> 8) & 0x3F;
        p2 = mNamespaceRequestCounts.size() & 0xFF;
    
        CommandApdu command = createCommandApduFromCbor(kINSGetNamespace, p1, p2, commandData.get(), &err); 
        
        if(err.err != CN_CBOR_NO_ERROR) {
            return ResultCode::INVALID_DATA;
        }

        ResponseApdu response = mAppletConnection.transmit(command);

        if(response.ok() && response.status() == AppletConnection::SW_OK){
            mCurrentNamespaceId++;
        } else {
            ALOGE("[%s] : Error during namespace initialization. ", __func__);
            return swToErrorMessage(response);
        }
    }

    p1 = 0;
    p2 = 0;

    // Encode the additional data and send it to the applet
    auto commandData = CBORPtr(encodeCborAdditionalData(nameSpace, name, accessControlProfileIds));

    if (commandData.get() == nullptr) {
        ALOGE("[%s] : Error initializing CBOR. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    CommandApdu command = createCommandApduFromCbor(kINSGetEntry, p1, p2, commandData.get(), &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error initializing CBOR. ", __func__);
        return ResultCode::INVALID_DATA;
    }

    ResponseApdu response = mAppletConnection.transmit(command);
    
    mCurrentValueEntrySize = entrySize;
    mCurrentValueDecryptedContent = 0;

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
        ALOGE("[%s] : Entry retrieval not started yet. ", __func__);
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

    std::vector<uint8_t> responseData;
    responseData.assign(response.dataBegin(), response.dataEnd());

    // Need to handle the first chunk differently as it encodes the full length of the entry
    if (firstChunk) {
        auto headerBegin = responseData.begin();
        // Get the length information
        uint8_t headerSize = decodeCborHeaderLength(*headerBegin);
        uint64_t chSize = responseData.size() - headerSize;
        if (headerSize == 0 || chSize > mCurrentValueEntrySize ||
            (encodedCborLength(chSize) + 1) > headerSize) {
            ALOGE("[%s] : Invalid chunk size, aborting! ", __func__);
            _hidl_cb(ResultCode::FAILED, result);
            return Void();
        }
        // Save the actual cbor length into buffer
        switch (headerSize) {
        case 9:
            *(headerBegin++) = ((chSize >> 56) & 0xffU);
            *(headerBegin++) = ((chSize >> 48) & 0xffU); 
            *(headerBegin++) = ((chSize >> 40) & 0xffU);
            *(headerBegin++) = ((chSize >> 32) & 0xffU); 
        [[clang::fallthrough]];
        case 5:
            *(headerBegin++) = ((chSize >> 24) & 0xffU);
            *(headerBegin++) = ((chSize >> 16) & 0xffU);
        [[clang::fallthrough]];
        case 3:
            *(headerBegin++) = ((chSize >> 8) & 0xffU);
        [[clang::fallthrough]];
        case 2:
            *(headerBegin++) = (chSize & 0xffU);
            break;
        case 1:
            *headerBegin &= 0xE0;
            *headerBegin |= (chSize & 0xffU);
            break;
        }
    }

    // Decode the decrypted content and return
    auto entryVal = CBORPtr(cn_cbor_decode(responseData.data(), responseData.size(), &err));

    if (entryVal.get() == nullptr) {
        _hidl_cb(ResultCode::INVALID_DATA, result);
        return Void();
    }

    // Check the data type
    int64_t entrySize = -1;
    std::vector<uint8_t> dataBytes;
    switch (entryVal.get()->type) {
        case CN_CBOR_BYTES:
            entrySize = entryVal.get()->length;
            mCurrentValueDecryptedContent += entrySize;
            dataBytes.assign(entryVal.get()->v.bytes, entryVal.get()->v.bytes + entrySize);
            result.byteString(dataBytes);
            break;
        case CN_CBOR_TEXT:
            entrySize = entryVal.get()->length;
            mCurrentValueDecryptedContent += entrySize;
            result.textString(hidl_string(entryVal.get()->v.str, entrySize));
            break;
        case CN_CBOR_INT:
            result.integer(entryVal.get()->v.sint);
            break;
        case CN_CBOR_UINT:
            result.integer(entryVal.get()->v.uint);
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
    
    if (entrySize == -1 || mCurrentValueDecryptedContent == mCurrentValueEntrySize) {
        // Finish this entry
        mCurrentNamespaceEntryCount--;

        if (!isLastChunk) {  // The estimate at the beginning was wrong: send final command to applet
            ALOGD("Full entry value decrypted, sending final command");
            
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
        ALOGE("[%s] : Entry retrieval not started yet.", __func__);
        _hidl_cb(ResultCode::FAILED, signature, auditLog);
        return Void();
    } else if (mCurrentNamespaceEntryCount != 0 ||
               mNamespaceRequestCounts.size() != mCurrentNamespaceId) {
        ALOGE("[%s] : Entry retrieval not finished yet.", __func__);
        _hidl_cb(ResultCode::FAILED, signature, auditLog);
        return Void();
    }

    auto commandData = CBORPtr(cn_cbor_array_create(&err));

    if (commandData.get() == nullptr) {
        _hidl_cb(ResultCode::FAILED, signature, auditLog);
        return Void();
    }

    if (mRequestDataDigest.size() != kDigestSize) {
        ALOGE("[%s] : Entry retrieval not successfully initialized. Mising request data digest.", __func__);
        _hidl_cb(ResultCode::INVALID_DATA, signature, auditLog);
        return Void();
    }

    if (!cn_cbor_array_append(commandData.get(), cn_cbor_data_create(prevAuditSignatureHash.data(),
                              prevAuditSignatureHash.size(), &err), &err) ||
        !cn_cbor_array_append(commandData.get(), cn_cbor_data_create(signingKeyBlob.data(), 
                              signingKeyBlob.size(), &err), &err)) {
        ALOGE("[%s] : Error encoding the provided data.", __func__);
        _hidl_cb(ResultCode::INVALID_DATA, signature, auditLog);
        return Void();
    }
    
    CommandApdu command = createCommandApduFromCbor(kINSCreateSignature, 0, 0, commandData.get(), &err);
    if(err.err != CN_CBOR_NO_ERROR) {
        ALOGE("[%s] : Error initializing CBOR object.", __func__);
        _hidl_cb(ResultCode::INVALID_DATA, signature, auditLog);
        return Void();
    }

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        ALOGE("[%s] : Signature creation failed.", __func__);
        _hidl_cb(swToErrorMessage(response), signature, auditLog);
        return Void();
    }

    auto cb_main = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));
    if (cb_main.get() == nullptr) {
        _hidl_cb(swToErrorMessage(response), signature, auditLog);
        return Void();
    }

    cn_cbor *cbor_auditSignature = cn_cbor_index(cb_main.get(), 0);
    cn_cbor *cbor_responseHash = cn_cbor_index(cb_main.get(), 1);
    cn_cbor *cbor_responseSignature = cn_cbor_index(cb_main.get(), 2);

    if (cbor_auditSignature == nullptr || cbor_responseHash == nullptr ||
        cbor_responseSignature == nullptr || cbor_auditSignature->type != CN_CBOR_BYTES ||
        cbor_responseHash->type != CN_CBOR_BYTES || cbor_responseSignature->type != CN_CBOR_BYTES ||
        cbor_auditSignature->v.bytes == nullptr || cbor_responseHash->v.bytes == nullptr ||
        cbor_responseSignature->v.bytes == nullptr || cbor_responseHash->length != kDigestSize) {
            
        ALOGE("[%s] : Error decoding SE response.", __func__);

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

    // Finish personalization
    mRetrievalStarted = false;
    mAppletConnection.close();

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
        ALOGE("[%s] : Credential could not be loaded.", __func__);
        _hidl_cb(result, signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    uint8_t p2 = 0;

    if (keyType != KeyType::EC_NIST_P_256) {
        ALOGE("[%s] : Elliptic curve not supported.", __func__);
        _hidl_cb(result, signingKeyBlob, signingKeyCertificate);
        return Void();
    } else {
        p2 = 1;
    }

    cn_cbor_errback err;

    // Create a signing key pair and return the result
    CommandApdu command{kCLAProprietary, kINSCreateSigningKey, 0, p2};
    ResponseApdu response = mAppletConnection.transmit(command);
    
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response), signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    auto cb_main = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));
    if (cb_main.get() == nullptr) {
        _hidl_cb(swToErrorMessage(response), signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    cn_cbor *cbor_signKeyBlob = cn_cbor_index(cb_main.get(), 0);
    cn_cbor *cbor_signingKeyCert = cn_cbor_index(cb_main.get(), 1);

    if (cbor_signKeyBlob == nullptr || cbor_signingKeyCert == nullptr ||
        cbor_signKeyBlob->type != CN_CBOR_BYTES || cbor_signingKeyCert->type != CN_CBOR_BYTES ||
        cbor_signKeyBlob->v.bytes == nullptr || cbor_signingKeyCert->v.bytes == nullptr) {
        ALOGE("[%s] : Error decoding SE response.", __func__);

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
