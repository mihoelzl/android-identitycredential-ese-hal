#ifndef ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIAL_H
#define ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIAL_H

#include <android/hardware/identity_credential/1.0/IIdentityCredential.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

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

struct IdentityCredential : public IIdentityCredential {
    // Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredential follow.
    Return<void> deleteCredential(deleteCredential_cb _hidl_cb) override;
    Return<void> createEphemeralKeyPair(::android::hardware::identity_credential::V1_0::KeyType keyType, createEphemeralKeyPair_cb _hidl_cb) override;
    Return<void> getEntries(const hidl_vec<hidl_vec<uint8_t>>& accessControlDescriptors, const hidl_vec<hidl_vec<uint8_t>>& entryBlobs, const ::android::hardware::keymaster::capability::V1_0::KeymasterCapability& authToken, const hidl_vec<uint8_t>& sessionTranscript, const hidl_vec<uint8_t>& readerSignature, const hidl_vec<uint8_t>& signingKeyBlob, const hidl_vec<hidl_vec<uint8_t>>& signingKeyChain, getEntries_cb _hidl_cb) override;
    Return<void> generateSigningKeyPair(::android::hardware::identity_credential::V1_0::KeyType keyType, generateSigningKeyPair_cb _hidl_cb) override;
    Return<::android::hardware::identity_credential::V1_0::Error> provisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& signingKeyBlob, const hidl_vec<hidl_vec<uint8_t>>& signingKeyCertificateChain) override;
    Return<void> getDirectAccessSigningKeyPairCounts(getDirectAccessSigningKeyPairCounts_cb _hidl_cb) override;
    Return<::android::hardware::identity_credential::V1_0::Error> deprovisionDirectAccessSigningKeyPair(const hidl_vec<uint8_t>& signingKeyBlob) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.

};

// FIXME: most likely delete, this is only for passthrough implementations
// extern "C" IIdentityCredential* HIDL_FETCH_IIdentityCredential(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIAL_H
