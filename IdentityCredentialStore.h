#ifndef ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIALSTORE_H
#define ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIALSTORE_H

#include <android/hardware/identity_credential/1.0/IIdentityCredentialStore.h>
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

struct IdentityCredentialStore : public IIdentityCredentialStore {
    // Methods from ::android::hardware::identity_credential::V1_0::IIdentityCredentialStore follow.
    Return<void> createCredential(const hidl_string& credentialType, bool testCredential, createCredential_cb _hidl_cb) override;
    Return<void> getCredential(const hidl_vec<uint8_t>& credentialBlob, getCredential_cb _hidl_cb) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.

};

// FIXME: most likely delete, this is only for passthrough implementations
// extern "C" IIdentityCredentialStore* HIDL_FETCH_IIdentityCredentialStore(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIALSTORE_H
