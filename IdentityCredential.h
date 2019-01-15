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

#ifndef ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIAL_H
#define ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIAL_H

#include "AppletConnection.h"

#include <android/hardware/identity_credential/1.0/IIdentityCredential.h>
#include <android/hardware/secure_element/1.0/ISecureElement.h>
#include <android/hardware/secure_element/1.0/ISecureElementHalCallback.h>
#include <android/hardware/secure_element/1.0/types.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

#include <cn-cbor/cn-cbor.h>

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;
using ::android::hardware::secure_element::V1_0::ISecureElement;
using ::android::hardware::secure_element::V1_0::ISecureElementHalCallback;
using ::android::hardware::keymaster::capability::V1_0::KeymasterCapability;

struct IdentityCredential : public IIdentityCredential {
    ~IdentityCredential();

    ResultCode initializeCredential(const hidl_vec<uint8_t>& credentialBlob);

    // Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredential follow.
    Return<void> deleteCredential(deleteCredential_cb _hidl_cb) override;
    Return<void> createEphemeralKeyPair(::android::hardware::identity_credential::V1_0::KeyType keyType, createEphemeralKeyPair_cb _hidl_cb) override;
    Return<void> startRetrieval(const StartRetrievalArguments& args, startRetrieval_cb _hidl_cb) override;
    Return<ResultCode> startRetrieveEntryValue(const hidl_string& nameSpace, const hidl_string& name, const hidl_vec<AccessControlProfileId>& accessControlProfileIds) override; 
    Return<void> retrieveEntryValue(const hidl_vec<uint8_t>& encryptedContent, retrieveEntryValue_cb _hidl_cb) override;
    Return<void> finishRetrieval(const hidl_vec<uint8_t>& signingKeyBlob, const hidl_vec<uint8_t>& previousAuditSignatureHash, finishRetrieval_cb _hidl_cb) override;
    Return<void> generateSigningKeyPair(::android::hardware::identity_credential::V1_0::KeyType keyType, generateSigningKeyPair_cb _hidl_cb) override;
    Return<ResultCode> provisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& signingKeyBlob, const hidl_vec<hidl_vec<uint8_t>>& signingKeyCertificateChain) override;
    Return<void> getDirectAccessSigningKeyPairStatus(getDirectAccessSigningKeyPairStatus_cb _hidl_cb) override;
    Return<ResultCode> deprovisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& signingKeyBlob) override;
    Return<ResultCode> configureDirectAccessPermissions(const hidl_vec<hidl_string>& itemsAllowedForDirectAccess) override;

private:
    ResultCode loadCredential();
    ResultCode loadEphemeralKey();

    ResultCode authenticateReader(hidl_vec<uint8_t> sessionTranscript,
                                  hidl_vec<uint8_t> readerAuthPubKey,
                                  hidl_vec<uint8_t> readerSignature);
    ResultCode authenticateUser(KeymasterCapability authToken);

    AppletConnection mAppletConnection;

    std::vector<uint8_t> mCredentialBlob = {};
    std::vector<uint16_t> mNamespaceRequestCounts = {};
    std::string mLoadedEphemeralKey;

    uint16_t mCurrentNamespaceId;
    uint16_t mCurrentNamespaceEntryCount;
    std::string mCurrentNamespaceName;
    
    // uint32_t mCurrentValueEntrySize;
    // uint32_t mCurrentValueEncryptedContent;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIAL_H
