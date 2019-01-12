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

#ifndef ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIALSTORE_H
#define ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIALSTORE_H

#include "AppletConnection.h"
#include "IdentityCredential.h"
#include "WritableIdentityCredential.h"

#include <android/hardware/identity_credential/1.0/IIdentityCredentialStore.h>
#include <android/hardware/secure_element/1.0/ISecureElement.h>
#include <android/hardware/secure_element/1.0/types.h>
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

    Return<void> getHardwareInformation(getHardwareInformation_cb _hidl_cb) override;

    Return<void> createCredential(const hidl_string& credentialType, bool testCredential, createCredential_cb _hidl_cb) override;
    Return<void> getCredential(const hidl_vec<uint8_t>& credentialBlob, getCredential_cb _hidl_cb) override;

private:

};

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_IDENTITYCREDENTIALSTORE_H
