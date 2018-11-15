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

#ifndef ANDROID_HARDWARE_CREDENTIAL_V1_0_CREDENTIAL_H
#define ANDROID_HARDWARE_CREDENTIAL_V1_0_CREDENTIAL_H

#include <android/hardware/credential/1.0/ICredential.h>
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

struct Credential : public ICredential {
    // Methods from ::android::hardware::credential::V1_0::ICredential follow.
    Return<void> del(del_cb _hidl_cb) override;
    Return<void> getEntries(const hidl_vec<hidl_vec<uint8_t>>& accessControlDescriptors, const hidl_vec<hidl_vec<uint8_t>>& entryBlobs, const ::android::hardware::keymaster::capability::V1_0::KeymasterCapability& authToken, const hidl_vec<uint8_t>& sessionTranscript, const hidl_vec<uint8_t>& readerSignature, const hidl_vec<uint8_t>& signingKeyBlob, getEntries_cb _hidl_cb) override;
    Return<void> generateSigningKeyPair(generateSigningKeyPair_cb _hidl_cb) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.

};

}  // namespace implementation
}  // namespace V1_0
}  // namespace credential
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_CREDENTIAL_V1_0_CREDENTIAL_H
