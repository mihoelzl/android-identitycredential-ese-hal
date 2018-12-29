/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_ICUTILS_H
#define ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_ICUTILS_H

#include "APDU.h"
#include "AppletConnection.h"

#include <android/hardware/identity_credential/1.0/types.h>

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_string;

template<typename iter_t>
std::string bytes_to_hex(iter_t begin, iter_t const& end) {
    std::ostringstream hex;
    hex << std::hex;
    while (begin != end)
        hex << static_cast<unsigned>(*begin++);
    return hex.str();
}

ResultCode swToErrorMessage(ResponseApdu& apdu){
    if(!apdu.ok()){
        return ResultCode::FAILED;
    }
    switch (apdu.status()){
        case AppletConnection::SW_INS_NOT_SUPPORTED:
            return ResultCode::UNSUPPORTED_OPERATION;

        case AppletConnection::SW_WRONG_LENGTH:
        case AppletConnection::SW_INCORRECT_PARAMETERS:
            return ResultCode::INVALID_DATA;        

        case AppletConnection::SW_SECURITY_CONDITIONS_NOT_SATISFIED:
        case AppletConnection::SW_CONDITIONS_NOT_SATISFIED:
            return ResultCode::RETRIEVAL_DENIED;
            
        case AppletConnection::SW_OK:
            return ResultCode::OK;

        default:
            return ResultCode::FAILED;
    }
}


}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
#endif  // ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_ICUTILS_H