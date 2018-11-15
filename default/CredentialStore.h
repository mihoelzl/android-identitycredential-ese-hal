#ifndef ANDROID_HARDWARE_CREDENTIAL_V1_0_CREDENTIALSTORE_H
#define ANDROID_HARDWARE_CREDENTIAL_V1_0_CREDENTIALSTORE_H

#include <android/hardware/credential/1.0/ICredentialStore.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace credential {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::sp;

struct CredentialStore : public ICredentialStore {
    // Methods from ::android::hardware::credential::V1_0::ICredentialStore follow.
    Return<void> createCredential(const hidl_vec<uint8_t>& iaKeyCertificate, const hidl_string& credentialType, const hidl_vec<::android::hardware::credential::V1_0::AccessControlProfile>& accessControlProfiles, const hidl_vec<::android::hardware::credential::V1_0::EntryConfiguration>& entries, const hidl_vec<uint8_t>& issuerSignature, bool testCredential, createCredential_cb _hidl_cb) override;
    Return<void> getCredential(const hidl_vec<uint8_t>& credentialBlob, getCredential_cb _hidl_cb) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.

};

// FIXME: most likely delete, this is only for passthrough implementations
// extern "C" ICredentialStore* HIDL_FETCH_ICredentialStore(const char* name);

}  // namespace implementation
}  // namespace V1_0
}  // namespace credential
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_CREDENTIAL_V1_0_CREDENTIALSTORE_H
