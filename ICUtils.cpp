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

CommandApdu createCommandApduFromCbor(uint8_t ins, uint8_t p1, uint8_t p2, cn_cbor* data,
                                          cn_cbor_errback* err) {
                                            
    unsigned char bufferSize = 1024u;
    std::vector<uint8_t> encoded{bufferSize};
    ssize_t enc_sz;

    enc_sz = cn_cbor_encoder_write(encoded.data(), 0, sizeof(bufferSize), data);
    if (enc_sz == -1) {
        err->err = CN_CBOR_ERR_OUT_OF_DATA;
        return CommandApdu{0,0,0,0};
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
            if (!cn_cbor_mapput_string(acp, "timeout",
                        cn_cbor_data_create(readerAuthPubKey.data(), readerAuthPubKey.size(), &err),
                        &err)) {
                cn_cbor_free(acp);
                return nullptr;
            }
        }
    }
    return acp;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android