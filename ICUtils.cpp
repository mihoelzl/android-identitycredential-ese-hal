/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "android.hardware.identity_credential@1.0-service"
#include <log/log.h>

#include "APDU.h"
#include "AppletConnection.h"

#include <android/hardware/identity_credential/1.0/types.h>
#include <cn-cbor/cn-cbor.h>

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

using ::android::hardware::keymaster::capability::V1_0::CapabilityType;

constexpr size_t kMaxBufferSize = 0x4001;
CommandApdu createCommandApduFromCbor(uint8_t ins, uint8_t p1, uint8_t p2, cn_cbor* data,
                                          cn_cbor_errback* err) {
    size_t bufferSize = 1024u;
    std::vector<uint8_t> encoded(bufferSize);
    ssize_t enc_sz = -1;

    while (enc_sz == -1 && bufferSize < kMaxBufferSize) {
        encoded.resize(bufferSize);
        enc_sz = cn_cbor_encoder_write(encoded.data(), 0, bufferSize, data);
        bufferSize = bufferSize * 2;
    }

    if (enc_sz == -1) {
        err->err = CN_CBOR_ERR_OUT_OF_DATA;
        return CommandApdu{0, 0, 0, 0};
    }
    
    // Send to applet
    CommandApdu command{0x80, ins, p1, p2, static_cast<size_t>(enc_sz), 0};
    std::copy(&encoded[0], &encoded[enc_sz], command.dataBegin());

    err->err = CN_CBOR_NO_ERROR;
    return command;
}

cn_cbor* encodeCborAccessControlProfile(uint64_t profileId, hidl_vec<uint8_t> readerAuthPubKey,
                                        uint64_t capabilityId, CapabilityType capabilityType,
                                        uint64_t timeout) {
    cn_cbor_errback err;
    cn_cbor* acp = cn_cbor_map_create(&err);

    if (err.err != CN_CBOR_NO_ERROR) {
        return nullptr;
    }
    if(!cn_cbor_mapput_string(acp, "id", cn_cbor_int_create(profileId, &err), &err)){
        cn_cbor_free(acp);
        return nullptr;
    }
    
    if(readerAuthPubKey.size() != 0){
        if (!cn_cbor_mapput_string(acp, "readerAuthPubKey",
                    cn_cbor_data_create(readerAuthPubKey.data(), readerAuthPubKey.size(), &err),
                    &err)) {
            cn_cbor_free(acp);
            return nullptr;
        }
    }
    if (capabilityId != 0) {
        if (!cn_cbor_mapput_string(acp, "capabilityType",
                                   cn_cbor_int_create(static_cast<uint32_t>(capabilityType), &err), &err)) {
            cn_cbor_free(acp);
            return nullptr;
        }
        if (!cn_cbor_mapput_string(acp, "capabilityId", cn_cbor_int_create(capabilityId, &err), &err)) {
            cn_cbor_free(acp);
            return nullptr;
        }
        if(timeout != 0){
            if (!cn_cbor_mapput_string(acp, "timeout", cn_cbor_int_create(timeout, &err), &err)) {
                cn_cbor_free(acp);
                return nullptr;
            }
        }
    }
    return acp;
}

cn_cbor* encodeCborNamespaceConf(std::string nameSpaceName, uint16_t nameSpaceEntryCount) {
    cn_cbor_errback err;

    cn_cbor* commandData = cn_cbor_array_create(&err);

    if (!cn_cbor_array_append(commandData,
                                cn_cbor_int_create(nameSpaceEntryCount, &err), &err)) {
        cn_cbor_free(commandData);
        return nullptr;
    }
    if (!cn_cbor_array_append(commandData, cn_cbor_string_create(nameSpaceName.c_str(), &err),
                                &err)) {
        cn_cbor_free(commandData);
        return nullptr;
    }
    return commandData;
}

cn_cbor* encodeCborAdditionalData(std::string nameSpaceName, std::string name,
                                  hidl_vec<uint8_t> accessControlProfileIds) {
    cn_cbor_errback err;
    cn_cbor* addData = cn_cbor_map_create(&err);

    if (err.err != CN_CBOR_NO_ERROR) {
        return nullptr;
    }
    if (!cn_cbor_mapput_string(addData, "namespace",
                               cn_cbor_string_create(nameSpaceName.c_str(), &err), &err)) {
        cn_cbor_free(addData);
        return nullptr;
    }
    if (!cn_cbor_mapput_string(addData, "name", cn_cbor_string_create(name.c_str(), &err), &err)) {
        cn_cbor_free(addData);
        return nullptr;
    }

    cn_cbor* profileIds = cn_cbor_array_create(&err);
    if (err.err != CN_CBOR_NO_ERROR) {
        cn_cbor_free(addData);
        return nullptr;
    }
    
    for (const auto& id : accessControlProfileIds) {
        if (!cn_cbor_array_append(profileIds, cn_cbor_int_create(id, &err), &err)) {
            cn_cbor_free(addData);
            cn_cbor_free(profileIds);
            return nullptr;
        }
    }

    if (!cn_cbor_mapput_string(addData, "accessControlProfileIds", profileIds, &err)) {
        cn_cbor_free(addData);
        cn_cbor_free(profileIds);
        return nullptr;
    }
    return addData;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android