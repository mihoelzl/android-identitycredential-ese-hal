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
#ifndef ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_APPLETCONNECTION_H
#define ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_APPLETCONNECTION_H

#include "APDU.h"

#include <android/hardware/identity_credential/1.0/types.h>
#include <android/hardware/secure_element/1.0/ISecureElement.h>
#include <android/hardware/secure_element/1.0/ISecureElementHalCallback.h>
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
using ::android::hardware::secure_element::V1_0::ISecureElement;
using ::android::hardware::secure_element::V1_0::ISecureElementHalCallback;

struct AppletConnection {
public:
    static constexpr size_t SW_WRONG_LENGTH = 0x6700;
    static constexpr size_t SW_SECURITY_CONDITIONS_NOT_SATISFIED = 0x6982;
    static constexpr size_t SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    static constexpr size_t SW_INCORRECT_PARAMETERS = 0x6A86;
    static constexpr size_t SW_INS_NOT_SUPPORTED = 0x6D00;
    static constexpr size_t SW_OK = 0x9000;

    /**
     * Connects to the secure element HAL service. Returns true if successful, false otherwise.
     */
    bool connectToSEService();

    /**
     * Select the applet on the secure element and returns the select response message.
     */
    ResponseApdu openChannelToApplet();

    /**
     * If open, closes the open channel to the applet. Returns an error message if channel was not
     * open or the SE HAL service returned an error.
     */
    ResultCode close();

    /**
     * Transmits the command APDU to the applet and response with the resulting Response APDU. If an
     * error occured during transmission, the ResponseApdu will be empty. If the applet returned an
     * error message, the ResponseApdu will contain a error message in ResponseApdu.status()
     */
    // const ResponseApdu<hidl_vec<uint8_t>> transmit(CommandApdu& command);
    const ResponseApdu transmit(CommandApdu& command);

    /**
     * Checks if a chennel to the applet is open.
     */
    bool isChannelOpen();

    /**
     * Return the maximum chunk size of the applet
     */
    uint16_t chunkSize() { return mChunkSize; }
private:
    sp<ISecureElement> mSEClient;

    uint16_t mApduMaxBufferSize = 255;
    uint16_t mChunkSize = 0;

    int8_t mOpenChannel = -1;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
#endif  // ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_APPLETCONNECTION_H
