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
// static constexpr uint8_t kINSCreateSignature = 0x3C;
static constexpr uint8_t kINSCreateSigningKey = 0x40;

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
    if (response.ok() && response.status() == AppletConnection::SW_OK) {

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
    } else {
        ALOGE("Error loading credential SW(%x)", response.status());
        _hidl_cb(ephKey);
    }
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
        // No reader authentication, only send session transcript
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

    // TODO(hoelzl) Do we need to add more into this structure?
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

Return<void> IdentityCredential::startRetrieval(const StartRetrievalArguments& args, startRetrieval_cb _hidl_cb){
    std::vector<uint8_t> failedIds;
    hidl_vec<uint8_t> readerAuthPubKey(0);

    // Check the incoming data
    // Get the reader pub key from the secure access control profile (only one profile should have it)
    for (auto& profile : args.accessControlProfiles) {
        if(profile.readerAuthPubKey.size() != 0) {
            if (readerAuthPubKey.size() != 0 && readerAuthPubKey != profile.readerAuthPubKey) {
                ALOGE("More than one profile with different reader auth pub key specified. Aborting!");
                _hidl_cb(ResultCode::INVALID_DATA, failedIds);
                return Void();
            }
            readerAuthPubKey = profile.readerAuthPubKey;
        }
    }
    // Initiate communication to applet 
    if (!mAppletConnection.isChannelOpen()) {
        ResponseApdu selectResponse = mAppletConnection.openChannelToApplet();
        if (!selectResponse.ok() || selectResponse.status() != AppletConnection::SW_OK) {
            _hidl_cb(swToErrorMessage(selectResponse), failedIds);
            return Void();
        }
    }

    // Load the credential blob and the ephemeral keys (if it has been initialized)
    ResultCode result = loadCredential();
    if (result != ResultCode::OK) {
        _hidl_cb(result, failedIds);
        return Void();
    }
    // Make sure that the ephemeral key for this identity credential is loaded
    if (mLoadedEphemeralKey.size() != 0) {
        result = loadEphemeralKey();
        if (result != ResultCode::OK) {
            _hidl_cb(result, failedIds);
            return Void();
        }
    }

    // Authenticate reader. If pubkey or signature is empty, only the session transcript will be
    // sent to the applet
    ResultCode authResult =
            authenticateReader(args.requestData, readerAuthPubKey, args.readerSignature);
    if (authResult != ResultCode::OK) {
        ALOGE("Reader authentication failed");
        _hidl_cb(authResult, failedIds);
        return Void();
    }
    // Authenticate the user with the keymastercapability token
    authResult = authenticateUser(args.authToken);
    if (authResult != ResultCode::OK) {
        ALOGE("User authentication failed");
        _hidl_cb(authResult, failedIds);
        return Void();
    }
    // DONE with authentication

    cn_cbor_errback err;
    // Load secure access control profiles onto the applet
    for (auto& profile : args.accessControlProfiles) {
        bool success = false;
        cn_cbor* commandData = cn_cbor_array_create(&err);
        if(err.err != CN_CBOR_NO_ERROR){
            ALOGE("Error initializing cbor object");
            failedIds.push_back(profile.id);

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
            failedIds.push_back(profile.id);
        }
        cn_cbor_free(commandData);
    }
    // DONE loading access control profiles

    // Save the request counts for later retrieval
    mNamespaceRequestCounts = args.requestCounts;

    _hidl_cb(ResultCode::OK, failedIds);
    return Void();
}

Return<ResultCode> IdentityCredential::startRetrieveEntryValue(
        const hidl_string& nameSpace, const hidl_string&  name,
        const hidl_vec<AccessControlProfileId>& accessControlProfileIds) {

    // Set the number of entries in p1p2
    uint8_t p1 = 0; 
    uint8_t p2 = 0; 
    cn_cbor_errback err;

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

        mCurrentNamespaceName = newNamespaceName;
        mCurrentNamespaceEntryCount = mNamespaceRequestCounts[mCurrentNamespaceId];

        cn_cbor* commandData =
                encodeCborNamespaceConf(mCurrentNamespaceName, mCurrentNamespaceEntryCount);
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
    // TODO: should we save the status?

    cn_cbor_free(commandData);
    return swToErrorMessage(response);
}

Return<void> IdentityCredential::retrieveEntryValue(const hidl_vec<uint8_t>& /* encryptedContent */,
                                                    retrieveEntryValue_cb /* _hidl_cb */) {
    // TODO implement
    return Void();
}

Return<void> IdentityCredential::finishRetrieval(
        const hidl_vec<uint8_t>& /* signingKeyBlob */,
        const hidl_vec<uint8_t>& /* previousAuditSignatureHash */, finishRetrieval_cb /* _hidl_cb */) {
            
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
        _hidl_cb(result, signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    uint8_t p2 = 0;

    if (keyType != KeyType::EC_NIST_P_256) {
        _hidl_cb(result, signingKeyBlob, signingKeyCertificate);
        return Void();
    } else {
        p2 = 1;
    }

    cn_cbor *cb;
    cn_cbor_errback err;

    // Create a signing key pair and return the result
    CommandApdu command{kCLAProprietary, kINSCreateSigningKey, 0, p2};
    ResponseApdu response = mAppletConnection.transmit(command);
    
    if (!response.ok() || response.status() != AppletConnection::SW_OK) {
        _hidl_cb(swToErrorMessage(response), signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    cb = cn_cbor_decode(&(*response.dataBegin()), response.dataSize(), &err);
    if (cb == nullptr) {
        _hidl_cb(swToErrorMessage(response), signingKeyBlob, signingKeyCertificate);
        return Void();
    }

    cn_cbor *cbor_signKeyBlob = cn_cbor_index(cb, 0);
    cn_cbor *cbor_signingKeyCert = cn_cbor_index(cb, 1);

    if (cbor_signKeyBlob == nullptr || cbor_signingKeyCert == nullptr ||
        cbor_signKeyBlob->type != CN_CBOR_BYTES || cbor_signingKeyCert->type != CN_CBOR_BYTES ||
        cbor_signKeyBlob->v.bytes == nullptr || cbor_signingKeyCert->v.bytes == nullptr) {
        ALOGE("Error decoding SE response");
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
