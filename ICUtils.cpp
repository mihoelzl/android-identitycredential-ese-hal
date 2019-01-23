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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

using ::android::hardware::keymaster::capability::V1_0::CapabilityType;

constexpr size_t kMaxBufferSize = 0x8000;

std::vector<uint8_t> encodeCborAsVector(const cn_cbor* data, cn_cbor_errback* err) {

    size_t bufferSize = 1024u;
    std::vector<uint8_t> encoded(bufferSize);
    ssize_t enc_sz = -1;

    while (enc_sz == -1 && bufferSize <= kMaxBufferSize) {
        encoded.resize(bufferSize);
        enc_sz = cn_cbor_encoder_write(encoded.data(), 0, bufferSize, data);
        bufferSize = bufferSize * 2;
    }

    if (enc_sz == -1) {
        err->err = CN_CBOR_ERR_OUT_OF_DATA;
        return std::vector<uint8_t>(0);
    }
    
    encoded.resize(enc_sz);
    return encoded;
}

CommandApdu createCommandApduFromCbor(const uint8_t ins, const uint8_t p1, const uint8_t p2,
                                      const cn_cbor* data, cn_cbor_errback* err) {
    std::vector dataAsVector = encodeCborAsVector(data, err);
    
    // Send to applet
    CommandApdu command{0x80, ins, p1, p2, dataAsVector.size(), 0};
    std::copy(dataAsVector.begin(), dataAsVector.end(), command.dataBegin());

    err->err = CN_CBOR_NO_ERROR;
    return command;
}

cn_cbor* encodeCborAccessControlProfile(const uint64_t profileId, const hidl_vec<uint8_t>& readerAuthPubKey,
                                        const uint64_t capabilityId, const CapabilityType capabilityType,
                                        const uint64_t timeout) {
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

cn_cbor* encodeCborNamespaceConf(const std::string& nameSpaceName, const uint16_t nameSpaceEntryCount) {
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

cn_cbor* encodeCborBoolean(const bool value, cn_cbor_errback* err){
    cn_cbor* cnBool = (cn_cbor*)calloc(1, sizeof(cn_cbor));

    if(cnBool == nullptr){
        err->err = CN_CBOR_ERR_OUT_OF_DATA;
        return nullptr;
    }

    err->err = CN_CBOR_NO_ERROR;
    cnBool->type = value ? CN_CBOR_TRUE : CN_CBOR_TRUE;
    
    return cnBool;
}

cn_cbor* encodeCborAdditionalData(const std::string& nameSpaceName,const std::string& name,
                                  const hidl_vec<uint8_t>& accessControlProfileIds) {
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

uint8_t decodeCborHeaderLength(const uint8_t firstByte) {
    uint8_t fb = firstByte & 0x1F;
    if(fb < 0x18) {
        return 1;
    } else if(fb == 0x19) {
        return 2;
    } else if(fb == 0x1a) {
        return 3;
    } else if(fb == 0x1b) {
        return 5;
    } else if(fb == 0x1c) {
        return 9;
    }
    return 0;
}

uint8_t encodedCborLength(const uint64_t val) {
    if (val < 24) return 0;
    for (size_t i = 1; i <= ((sizeof val) >> 1); i <<= 1) {
        if (!(val >> (i << 3))) return i;
    }
    return sizeof val;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> ret;
    ret.resize(SHA256_DIGEST_LENGTH);
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data.data(), data.size());
    SHA256_Final((unsigned char*)ret.data(), &c);
    return ret;
}


struct EC_KEY_Deleter {
    void operator()(EC_KEY* key) const {
        if (key != nullptr) {
            EC_KEY_free(key);
        }
    }
};

using EC_KEY_Ptr = std::unique_ptr<EC_KEY, EC_KEY_Deleter>;

struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* key) const {
        if (key != nullptr) {
            EVP_PKEY_free(key);
        }
    }
};

using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

struct EC_GROUP_Deleter {
    void operator()(EC_GROUP* group) const {
        if (group != nullptr) {
            EC_GROUP_free(group);
        }
    }
};

using EC_GROUP_Ptr = std::unique_ptr<EC_GROUP, EC_GROUP_Deleter>;

struct BIGNUM_Deleter {
    void operator()(BIGNUM* bignum) const {
        if (bignum != nullptr) {
            BN_free(bignum);
        }
    }
};

using BIGNUM_Ptr = std::unique_ptr<BIGNUM, BIGNUM_Deleter>;

hidl_vec<uint8_t> encodeECPrivateKey(const cn_cbor* cb_privKey, cn_cbor_errback* err) {
    hidl_vec<uint8_t> ephKey;

    // Parse received data as EC private key
    auto pkey = EC_KEY_Ptr(EC_KEY_new());
    auto group = EC_GROUP_Ptr(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    if (pkey.get() == nullptr || group.get() == nullptr ||
        EC_KEY_set_group(pkey.get(), group.get()) != 1) {
        err->err = CN_CBOR_ERR_OUT_OF_MEMORY;
        return ephKey;
    }
    auto bn = BIGNUM_Ptr(BN_bin2bn(cb_privKey->v.bytes, cb_privKey->length, nullptr));

    if (EC_KEY_set_private_key(pkey.get(), bn.get()) != 1) {
        err->err = CN_CBOR_ERR_OUT_OF_MEMORY;
        return ephKey;
    }

    // Create a PKCS#8 object from the private key
    auto keyPair = EVP_PKEY_Ptr(EVP_PKEY_new());
    if (EVP_PKEY_set1_EC_KEY(keyPair.get(), pkey.get()) != 1) {
        err->err = CN_CBOR_ERR_INVALID_PARAMETER;
        return ephKey;
    }

    ssize_t size = i2d_PrivateKey(keyPair.get(), nullptr);
    if (size == 0) {
        err->err = CN_CBOR_ERR_INVALID_PARAMETER;
        return ephKey;
    }
    ephKey.resize(size);
    uint8_t *p = ephKey.data();
    i2d_PrivateKey(keyPair.get(), &p);

    err->err = CN_CBOR_NO_ERROR;
    return ephKey;
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android