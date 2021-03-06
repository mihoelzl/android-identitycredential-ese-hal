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

#include <android/hardware/identity_credential/1.0/IIdentityCredentialStore.h>
#include <hidl/HidlTransportSupport.h>
#include <log/log.h>

#include "IdentityCredentialStore.h"

using android::hardware::identity_credential::V1_0::IIdentityCredentialStore;
using android::hardware::identity_credential::V1_0::implementation::IdentityCredentialStore;

using android::OK;
using android::sp;
using android::status_t;
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;

int main() {
    ::android::hardware::configureRpcThreadpool(1, true /* willJoinThreadpool */);

    sp<IIdentityCredentialStore> credentialstore = new IdentityCredentialStore();

    const status_t status = credentialstore->registerAsService();
    if (status != android::OK) {
        LOG_ALWAYS_FATAL("Could not register service for Identity Credential Store 1.0 (%d)",
                         status);
        return 1;
    }

    ALOGD("Identity Credential Service is ready");
    ::android::hardware::joinRpcThreadpool();
    return -1;  // Should never get here.
}
