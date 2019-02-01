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
#include "IdentityCredentialStore.h"
#include "APDU.h"
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

Result IdentityCredential::initializeCredential(const hidl_vec<uint8_t>& credentialData){

    if (!mAppletConnection.connectToSEService()) {
        return result(ResultCode::FAILED, "Error while trying to connect to SE service");
    }
   
    mCredentialBlob = credentialData;
    
    return resultOk();
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
    if (!mRetrievalStarted) {
        ALOGE("Retrieval not started yet");
        return false;
    }
    return true;
}

Result IdentityCredential::loadCredential(){
    // Send the command to the applet to load the applet
    CommandApdu command{kCLAProprietary, kINSLoadCredential, 0, 0, mCredentialBlob.size(), 0};
    std::copy(mCredentialBlob.begin(), mCredentialBlob.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);
    return swToErrorMessage(response, "Error loading credentialData");
}

Result IdentityCredential::loadEphemeralKey() {
    CommandApdu command{kCLAProprietary, kINSLoadEphemeralKey, 0x80, 0, mLoadedEphemeralKey.size(), 0};
    std::copy(mLoadedEphemeralKey.begin(), mLoadedEphemeralKey.end(), command.dataBegin());

    ResponseApdu response = mAppletConnection.transmit(command);
    return swToErrorMessage(response, "Error loading ephemeral key");
}


Return<void> IdentityCredential::deleteCredential(deleteCredential_cb /*_hidl_cb*/) {
    // TODO
    return Void();
}

Return<void> IdentityCredential::createEphemeralKeyPair(createEphemeralKeyPair_cb _hidl_cb) {
    hidl_vec<uint8_t> emptyEphKey;
    uint8_t p1 = 0;
    uint8_t p2 = 1; // EC_NIST_P_256

    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(result(ResultCode::FAILED, "Could not select the applet. "), emptyEphKey);
            return Void();
        }
    }

    Result loadResult = loadCredential();
    if (loadResult.code != ResultCode::OK) {
        _hidl_cb(loadResult, emptyEphKey);
        return Void();
    }

    CommandApdu command{kCLAProprietary, kINSLoadEphemeralKey, p1, p2};
    ResponseApdu response = mAppletConnection.transmit(command);

    // Check response
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response, "Error creating ephemeral key"), emptyEphKey);
        return Void();
    }

    // Decode the ephemeral keypair and the mac
    cn_cbor_errback err;
    auto cborResponse = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));

    if (cborResponse.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response."), emptyEphKey);
        return Void();
    }

    cn_cbor *cb_ephPubKey = cn_cbor_index(cborResponse.get(), 0);
    cn_cbor *cb_ephPrivKey = cn_cbor_index(cborResponse.get(), 1);
    cn_cbor *cb_pkMac = cn_cbor_index(cborResponse.get(), 2);

    if (cb_ephPubKey == nullptr || cb_ephPrivKey == nullptr || cb_pkMac == nullptr ||
        cb_ephPubKey->type != CN_CBOR_BYTES || cb_ephPrivKey->type != CN_CBOR_BYTES ||
        cb_pkMac->type != CN_CBOR_BYTES || cb_ephPubKey->v.bytes == nullptr ||
        cb_ephPrivKey->v.bytes == nullptr || cb_pkMac->v.bytes == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response."), emptyEphKey);
        return Void();
    }

    // Save the ephemeral key and the MAC as cbor structure (see loadEphemeralKey)
    auto cborStructureemptyEphKey = CBORPtr(cn_cbor_array_create(&err));
    if (cborStructureemptyEphKey.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error initializing CBOR structure."), emptyEphKey);
        return Void();
    }
    if (!cn_cbor_array_append(cborStructureemptyEphKey.get(),
                              cn_cbor_data_create(cb_ephPubKey->v.bytes, cb_ephPubKey->length, &err),
                              &err) ||
        !cn_cbor_array_append(cborStructureemptyEphKey.get(),
                              cn_cbor_data_create(cb_pkMac->v.bytes, cb_pkMac->length, &err),
                              &err)) {
        _hidl_cb(result(ResultCode::FAILED, "Error initializing CBOR structure."), emptyEphKey);
        return Void();
    }
    
    mLoadedEphemeralKey = encodeCborAsVector(cborStructureemptyEphKey.get(), &err);

    // Parse received data as ec private key
    hidl_vec<uint8_t> ephKey = encodeECPrivateKey(cb_ephPrivKey, &err);

    if (err.err != CN_CBOR_NO_ERROR) {
        _hidl_cb(result(ResultCode::FAILED, "Error encoding ephemeral key pair."), emptyEphKey);
        return Void();
    }

    _hidl_cb(resultOk(), ephKey);

    return Void();
}

Result IdentityCredential::authenticateReader(const hidl_vec<uint8_t>& readerAuthData,
                                                  const hidl_vec<uint8_t>& readerPubKey,
                                                  const hidl_vec<uint8_t>& signature) {
    uint8_t p2 = 0;
    cn_cbor_errback err;

    auto cmdData = CBORPtr(cn_cbor_array_create(&err));
    if (cmdData.get() == nullptr) {
        return result(ResultCode::INVALID_DATA, "Error initializing CBOR structure.");
    }

    cn_cbor_array_append(cmdData.get(),
                         cn_cbor_data_create(readerAuthData.data(),
                                             readerAuthData.size(), &err),
                         &err);

    if (err.err != CN_CBOR_NO_ERROR) {
        return result(ResultCode::INVALID_DATA, "Error initializing CBOR structure.");
    }

    if (readerPubKey.size() != 0 && signature.size() != 0) {
        // Authenticate reader
        p2 = 1;

        if (!cn_cbor_array_append(cmdData.get(), 
                    cn_cbor_data_create(readerPubKey.data(), readerPubKey.size(), &err), &err) ||
            !cn_cbor_array_append(cmdData.get(), 
                    cn_cbor_data_create(signature.data(), signature.size(), &err), &err)) {
            return result(ResultCode::INVALID_DATA, "Error initializing CBOR structure.");
        }
    } else {
        // No reader authentication, only send readerAuthData
        p2 = 0;
    }

    // TODO: parse the ephemeral reader public key from session transcript
    mReaderEphPubKey = readerPubKey;

    CommandApdu command = createCommandApduFromCbor(kINSAuthenticate, 0, p2, cmdData.get(), &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        return result(ResultCode::INVALID_DATA, "Error initializing CBOR structure.");
    }

    ResponseApdu response = mAppletConnection.transmit(command);

    return swToErrorMessage(response, "Failed to authenticate reader");
}

Result IdentityCredential::authenticateUser(const KeymasterCapability& authToken) {
    uint8_t p2 = 2;
    cn_cbor_errback err;

    auto cmdData = CBORPtr(cn_cbor_array_create(&err));

    if (cmdData.get() == nullptr) {
        return result(ResultCode::INVALID_DATA, "Error initializing CBOR structure.");
    }

    // TODO Do we need to add more for authentication?
    if (!cn_cbor_array_append(cmdData.get(), cn_cbor_int_create(authToken.challenge, &err), &err) ||
        !cn_cbor_array_append(cmdData.get(), cn_cbor_int_create(authToken.timestamp, &err), &err) ||
        !cn_cbor_array_append(cmdData.get(), cn_cbor_data_create(authToken.secure_token.data(),
                                                  authToken.secure_token.size(), &err), &err)) {
        return result(ResultCode::INVALID_DATA, "Error initializing CBOR structure.");
    }

    CommandApdu command = createCommandApduFromCbor(kINSAuthenticate, 0, p2, cmdData.get(), &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        return result(ResultCode::INVALID_DATA,"Error initializing CBOR structure.");
    }

    ResponseApdu response = mAppletConnection.transmit(command);
    
    return swToErrorMessage(response, "Failed to authenticate user");
}

Return<void> IdentityCredential::startRetrieval(const StartRetrievalArguments& args,
                                                startRetrieval_cb _hidl_cb) {
    hidl_vec<uint8_t> readerAuthPubKey(0);

    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(result(ResultCode::FAILED, "Applet could not be selected."));
            return Void();
        }
    }

    // Check the incoming data
    // Get the reader pub key from the secure access control profile (only one profile should have it)
    for (const auto& profile : args.accessControlProfiles) {
        if (profile.readerCertificate.size() != 0) {
            if (readerAuthPubKey.size() != 0 && readerAuthPubKey != profile.readerCertificate) {
                _hidl_cb(result(
                        ResultCode::INVALID_DATA,
                        "More than one profile with different reader auth pub key specified."));
                return Void();
            }
            readerAuthPubKey = getECPublicKeyFromCertificate(profile.readerCertificate);

            if (readerAuthPubKey.size() == 0) {
                _hidl_cb(result(ResultCode::INVALID_DATA, "Certificate parsing error."));
                return Void();
            }
        }
    }
    // Initiate communication to applet 
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(result(ResultCode::FAILED, "Could not select the applet."));
            return Void();
        }
    }

    resetRetrievalState();

    // Load the credential blob and the ephemeral keys (if it has been initialized)
    Result loadResult = loadCredential();
    if (loadResult.code != ResultCode::OK) {
        _hidl_cb(loadResult);
        return Void();
    }
    // Make sure that the ephemeral key for this identity credential is loaded
    if (mLoadedEphemeralKey.size() != 0) {
        loadResult = loadEphemeralKey();
        if (loadResult.code != ResultCode::OK) {
            _hidl_cb(loadResult);
            return Void();
        }
    }

    if (args.requestData.size() == 0) {
        _hidl_cb(result(ResultCode::INVALID_DATA, "Request data cannot be empty."));
        return Void();
    }

    // Authenticate reader. If pubkey or signature is empty, only the session transcript will be
    // sent to the applet
    Result authResult =
            authenticateReader(args.requestData, readerAuthPubKey, args.readerSignature);
    if (authResult.code != ResultCode::OK) {
        _hidl_cb(authResult);
        return Void();
    }
    // Authenticate the user with the keymastercapability token
    authResult = authenticateUser(args.authToken);
    if (authResult.code != ResultCode::OK) {
        _hidl_cb(authResult);
        return Void();
    }
    // DONE with authentication
    
    // Sort access control profiles by their ID
    std::vector<SecureAccessControlProfile> localSACP = args.accessControlProfiles;
    std::sort(localSACP.begin(), localSACP.end(), AccessControlComparator());

    cn_cbor_errback err;
    // Load secure access control profiles onto the applet
    for (const auto& profile : localSACP) {
        auto commandData = CBORPtr(cn_cbor_array_create(&err));
        if (commandData.get() == nullptr) {
            _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization. "));
            return Void();
        }

        cn_cbor* acp = encodeCborAccessControlProfile(
                profile.id, getECPublicKeyFromCertificate(profile.readerCertificate),
                profile.capabilityId, profile.capabilityType, profile.timeout);

        // Append Access Control profile and MAC
        if (acp == nullptr || !cn_cbor_array_append(commandData.get(), acp, &err)){
            cn_cbor_free(acp);
            _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization. "));
            return Void();
        }

        if (!cn_cbor_array_append(commandData.get(),
                                  cn_cbor_data_create(profile.mac.data(), profile.mac.size(), &err),
                                  &err)) {
            _hidl_cb(result(ResultCode::FAILED, "Error adding MAC to CBOR structure. "));
            return Void();
        }

        // Send command
        CommandApdu command = createCommandApduFromCbor(kINSLoadAccessControlProfile, 0, 0,
                                                        commandData.get(), &err);

        if (err.err != CN_CBOR_NO_ERROR) {
            _hidl_cb(result(ResultCode::FAILED, "Error creating Command APDU "));
            return Void();
        }

        ResponseApdu response = mAppletConnection.transmit(command);

        if (!response.ok() || response.status() != AppletConnection::SW_OK) {
            _hidl_cb(result(ResultCode::ACCESS_DENIED, "Error initializing access control profile. "));
            return Void();
        }
    }
    // DONE loading access control profiles

    // Save the request counts for later retrieval
    mNamespaceRequestCounts = args.requestCounts;
    mRetrievalStarted = true;
    mRequestDataDigest = sha256(args.requestData);

    _hidl_cb(resultOk());
    return Void();
}

Return<void> IdentityCredential::startRetrieveEntryValue(
        const hidl_string& nameSpace, const hidl_string& name, uint32_t entrySize,
        const hidl_vec<uint8_t>& accessControlProfileIds, startRetrieveEntryValue_cb _hidl_cb) {
    uint8_t p1 = 0; 
    uint8_t p2 = 0; 
    cn_cbor_errback err;

    if (!verifyAppletRetrievalStarted()) {
        _hidl_cb(result(ResultCode::FAILED, "Entry retrieval did not start yet. "));
        return Void();
    } else if (mCurrentNamespaceEntryCount == 0 &&
               mNamespaceRequestCounts.size() == mCurrentNamespaceId) {
        _hidl_cb(result(ResultCode::FAILED, "Entries have already been retrieved. "));
        return Void();
    }

    if (nameSpace.size() == 0 || name.size() == 0) {
        _hidl_cb(result(ResultCode::INVALID_DATA, "Namespace and name cannot be empty."));
        return Void();
    }

    if (mCurrentNamespaceEntryCount == 0 && mCurrentNamespaceName != nameSpace) {
        mCurrentNamespaceEntryCount = mNamespaceRequestCounts[mCurrentNamespaceId];

        auto commandData = CBORPtr(encodeCborNamespaceConf(nameSpace, mCurrentNamespaceEntryCount));
        if (commandData.get() == nullptr) {
            _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization. "));
            return Void();
        }

        // Set the number of namespaces in p1p2
        p1 = (mNamespaceRequestCounts.size() >> 8) & 0x3F;
        p2 = mNamespaceRequestCounts.size() & 0xFF;

        CommandApdu command =
                createCommandApduFromCbor(kINSGetNamespace, p1, p2, commandData.get(), &err);

        if (err.err != CN_CBOR_NO_ERROR) {
            _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization. "));
            return Void();
        }

        ResponseApdu response = mAppletConnection.transmit(command, true);

        if (response.ok() && response.status() == AppletConnection::SW_OK) {
            mCurrentNamespaceName = nameSpace;
            mCurrentNamespaceId++;
        } else {
            _hidl_cb(swToErrorMessage(response, "Error during namespace initialization. "));
            return Void();
        }
    } else if (mCurrentNamespaceName != nameSpace) {
        _hidl_cb(result(ResultCode::FAILED,
                        "Cannot start a new namespace, %hu entries remain to be retrieved.",
                        __func__, mCurrentNamespaceEntryCount));
        return Void();
    } else if (mCurrentNamespaceEntryCount == 0) {
        _hidl_cb(result(ResultCode::FAILED,
                        "No more entries remain to be retrieved for this namespace. "));
        return Void();
    }

    p1 = 0;
    p2 = 0;

    // Encode the additional data and send it to the applet
    auto commandData = CBORPtr(encodeCborAdditionalData(nameSpace, name, accessControlProfileIds));

    if (commandData.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization. "));
        return Void();
    }

    CommandApdu command = createCommandApduFromCbor(kINSGetEntry, p1, p2, commandData.get(), &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization. "));
        return Void();
    }

    ResponseApdu response = mAppletConnection.transmit(command);

    if (response.ok() && response.status() == AppletConnection::SW_OK) {
        mCurrentValueEntrySize = entrySize;
        mCurrentValueDecryptedContent = 0;
    }

    _hidl_cb(swToErrorMessage(response, "Failed to start entry retrieval on applet"));
    return Void();
}

Return<void> IdentityCredential::retrieveEntryValue(const hidl_vec<uint8_t>& encryptedContent,
                                                    retrieveEntryValue_cb _hidl_cb) {
    EntryValue valueResult;
    uint8_t p1 = 0;  
    uint8_t p2 = 0; 
    cn_cbor_errback err;
    bool isLastChunk = false;
    bool firstChunk = false;

    if (!verifyAppletRetrievalStarted()) {
        _hidl_cb(result(ResultCode::FAILED, "Entry retrieval not started yet. "), valueResult);
        return Void();
    }
    if (encryptedContent.size() == 0) {
        _hidl_cb(result(ResultCode::INVALID_DATA, "Invalid data size. "), valueResult);
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

        // Estimate if this will be the last chunk. Note: we actually do not know the size of the
        // decrypted content (size of the CBOR header was added by HAL). Issue at corner case where
        // entry + encryption overhead + CBOR header size exceeds chunk. To be safe, check with
        // maximum CBOR header size of 9
        size_t estSize = (mCurrentValueDecryptedContent + encryptedContent.size() -
                           IdentityCredentialStore::ENCRYPTION_OVERHEAD -
                           IdentityCredentialStore::MAX_CBOR_HEADER);
        // Also check that this is not the first chunk as well
        if (estSize >= mCurrentValueEntrySize && mCurrentValueDecryptedContent != 0) { 
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
        _hidl_cb(swToErrorMessage(response, "Entry retrieval from applet failed"), valueResult);
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
            _hidl_cb(result(ResultCode::FAILED, "Invalid chunk size. "), valueResult);
            return Void();
        }
        // Save the actual cbor length into buffer
        switch (headerSize) {
        case 9:
            *(++headerBegin) = ((chSize >> 56) & 0xffU);
            *(++headerBegin) = ((chSize >> 48) & 0xffU); 
            *(++headerBegin) = ((chSize >> 40) & 0xffU);
            *(++headerBegin) = ((chSize >> 32) & 0xffU); 
        [[clang::fallthrough]];
        case 5:
            *(++headerBegin) = ((chSize >> 24) & 0xffU);
            *(++headerBegin) = ((chSize >> 16) & 0xffU);
        [[clang::fallthrough]];
        case 3:
            *(++headerBegin) = ((chSize >> 8) & 0xffU);
        [[clang::fallthrough]];
        case 2:
            *(++headerBegin) = (chSize & 0xffU);
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
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response"), valueResult);
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
            valueResult.byteString(dataBytes);
            break;
        case CN_CBOR_TEXT:
            entrySize = entryVal.get()->length;
            mCurrentValueDecryptedContent += entrySize;

            dataBytes.resize(entrySize);
            std::copy(entryVal.get()->v.str, entryVal.get()->v.str + entrySize, dataBytes.begin());

            valueResult.textString(dataBytes);
            break;
        case CN_CBOR_INT:
            valueResult.integer(entryVal.get()->v.sint);
            break;
        case CN_CBOR_UINT:
            valueResult.integer(entryVal.get()->v.uint);
            break;
        case CN_CBOR_TRUE:
            valueResult.booleanValue(true);
            break;
        case CN_CBOR_FALSE:
            valueResult.booleanValue(false);
            break;
        default:
            _hidl_cb(result(ResultCode::INVALID_DATA, "Decrypted data invalid. "), valueResult);
            return Void();
    }
    
    if (entrySize == -1 || mCurrentValueDecryptedContent == mCurrentValueEntrySize) {
        // Finish this entry
        mCurrentNamespaceEntryCount--;

        if (!isLastChunk) {  // The estimate at the beginning was wrong: send final command to applet
            p1 |= 0x1;
            CommandApdu command{kCLAProprietary, kINSGetEntry, p1, p2};                     
            ResponseApdu response = mAppletConnection.transmit(command);

            if (!response.ok() || response.status() != AppletConnection::SW_OK) {
                _hidl_cb(swToErrorMessage(response, "Failed to finish entry retriefal"),
                         valueResult);
                return Void();
            }
        }
    }
    
    _hidl_cb(resultOk(), valueResult);
    return Void();
}

Return<void> IdentityCredential::finishRetrieval(
        const hidl_vec<uint8_t>& signingKeyBlob,
        const hidl_vec<uint8_t>& prevAuditSignatureHash, finishRetrieval_cb _hidl_cb) {
            
    AuditLogEntry auditLog;
    cn_cbor_errback err;
    hidl_vec<uint8_t> signature;

    if (!verifyAppletRetrievalStarted()) {
        _hidl_cb(result(ResultCode::FAILED, "Entry retrieval not started yet. "), signature,
                 auditLog);
        return Void();
    } else if (mCurrentNamespaceEntryCount != 0 ||
               mNamespaceRequestCounts.size() != mCurrentNamespaceId) {
        _hidl_cb(result(ResultCode::FAILED, "Entry retrieval not finished yet."), signature,
                 auditLog);
        return Void();
    }
    if (signingKeyBlob.size() == 0 || prevAuditSignatureHash.size() != kDigestSize) {
        _hidl_cb(result(ResultCode::INVALID_DATA, "Invalid data size."), signature, auditLog);
        return Void();
    }

    auto commandData = CBORPtr(cn_cbor_array_create(&err));

    if (commandData.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error in CBOR initalization. "), signature, auditLog);
        return Void();
    }

    if (mRequestDataDigest.size() != kDigestSize) {
        _hidl_cb(
                result(ResultCode::INVALID_DATA,
                       "Entry retrieval not successfully initialized. Mising request data digest."),
                signature, auditLog);
        return Void();
    }

    if (!cn_cbor_array_append(commandData.get(), cn_cbor_data_create(prevAuditSignatureHash.data(),
                              prevAuditSignatureHash.size(), &err), &err) ||
        !cn_cbor_array_append(commandData.get(), cn_cbor_data_create(signingKeyBlob.data(), 
                              signingKeyBlob.size(), &err), &err) || 
        !cn_cbor_array_append(commandData.get(), cn_cbor_data_create(mReaderEphPubKey.data(), 
                              mReaderEphPubKey.size(), &err), &err)) {
        _hidl_cb(result(ResultCode::FAILED, "Error encoding the provided data."), signature,
                 auditLog);
        return Void();
    }

    CommandApdu command =
            createCommandApduFromCbor(kINSCreateSignature, 0, 0, commandData.get(), &err);
    if (err.err != CN_CBOR_NO_ERROR) {
        _hidl_cb(result(ResultCode::FAILED, "Failed to initialize CBOR object."), signature,
                 auditLog);
        return Void();
    }

    ResponseApdu response = mAppletConnection.transmit(command);

    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response, "Signature creation failed"), signature, auditLog);
        return Void();
    }

    auto cb_main = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));
    if (cb_main.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Failed to decode SE response."), signature,
                 auditLog);
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
            
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response."), signature, auditLog);
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

    _hidl_cb(resultOk(), signature, auditLog);

    return Void();
}

Return<void> IdentityCredential::generateSigningKeyPair(generateSigningKeyPair_cb _hidl_cb) {
    hidl_vec<uint8_t> signingKeyCertificate;
    hidl_vec<uint8_t> signingKeyBlob;
    uint8_t p2 = 1; // EC_NIST_P_256

    // Initiate communication to applet 
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(result(ResultCode::FAILED, "Could not select the applet."), signingKeyBlob,
                     signingKeyCertificate);
            return Void();
        }
    }

    // Load the credential blob and the ephemeral keys (if it has been initialized)
    Result loadResult = loadCredential();
    if (loadResult.code != ResultCode::OK) {
        _hidl_cb(loadResult, signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    cn_cbor_errback err;

    // Create a signing key pair and return the result
    CommandApdu command{kCLAProprietary, kINSCreateSigningKey, 0, p2};
    ResponseApdu response = mAppletConnection.transmit(command);
    
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(result(ResultCode::FAILED, "Signing key creation failed."), signingKeyBlob,
                 signingKeyCertificate);
        return Void();
    }

    auto cb_main = CBORPtr(cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err));
    if (cb_main.get() == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response."), signingKeyBlob,
                 signingKeyCertificate);
        return Void();
    }

    cn_cbor *cbor_signKeyBlob = cn_cbor_index(cb_main.get(), 0);
    cn_cbor *cbor_signingKeyCert = cn_cbor_index(cb_main.get(), 1);

    if (cbor_signKeyBlob == nullptr || cbor_signingKeyCert == nullptr ||
        cbor_signKeyBlob->type != CN_CBOR_BYTES || cbor_signingKeyCert->type != CN_CBOR_BYTES ||
        cbor_signKeyBlob->v.bytes == nullptr || cbor_signingKeyCert->v.bytes == nullptr) {
        _hidl_cb(result(ResultCode::FAILED, "Error decoding SE response."), signingKeyBlob,
                 signingKeyCertificate);
        return Void();
    }

    signingKeyBlob.resize(cbor_signKeyBlob->length);
    signingKeyCertificate.resize(cbor_signingKeyCert->length);

    std::copy(cbor_signKeyBlob->v.bytes, cbor_signKeyBlob->v.bytes + cbor_signKeyBlob->length,
              signingKeyBlob.begin());
    std::copy(cbor_signingKeyCert->v.bytes,
              cbor_signingKeyCert->v.bytes + cbor_signingKeyCert->length,
              signingKeyCertificate.begin());

    _hidl_cb(resultOk(), signingKeyBlob, signingKeyCertificate);
    
    return Void();
}

Return<void>
IdentityCredential::provisionDirectAccessSigningKeyPair(
    const hidl_vec<uint8_t>& /*signingKeyBlob*/,
    const hidl_vec<hidl_vec<uint8_t>>& /*signingKeyCertificateChain*/,
    provisionDirectAccessSigningKeyPair_cb _hidl_cb) {
    _hidl_cb(result(ResultCode::UNSUPPORTED_OPERATION, ""));
    return Void();
}

Return<void> IdentityCredential::getDirectAccessSigningKeyPairStatus(
    getDirectAccessSigningKeyPairStatus_cb _hidl_cb) {
    hidl_vec<DirectAccessSigningKeyStatus> empty;
    _hidl_cb(result(ResultCode::UNSUPPORTED_OPERATION, ""), empty, 0);
    return Void();
}

Return<void> IdentityCredential::deprovisionDirectAccessSigningKeyPair(
        const hidl_vec<uint8_t>& /*signingKeyBlob*/,
        deprovisionDirectAccessSigningKeyPair_cb _hidl_cb) {
    _hidl_cb(result(ResultCode::UNSUPPORTED_OPERATION, ""));
    return Void();
}

Return<void> IdentityCredential::configureDirectAccessPermissions(
        const hidl_vec<hidl_string>& /* itemsAllowedForDirectAccess */,
        configureDirectAccessPermissions_cb _hidl_cb) {
    _hidl_cb(result(ResultCode::UNSUPPORTED_OPERATION, ""));
    return Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
