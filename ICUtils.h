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

#ifndef ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_ICUTILS_H
#define ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_ICUTILS_H

#include "APDU.h"
#include "AppletConnection.h"

#include <android/hardware/identity_credential/1.0/types.h>
#include <cn-cbor/cn-cbor.h>

#include <iomanip>
#include <android-base/stringprintf.h>

namespace android {
namespace hardware {
namespace identity_credential {
namespace V1_0 {
namespace implementation {

using ::android::hardware::hidl_string;
using ::android::hardware::keymaster::capability::V1_0::CapabilityType;

/**
 * Convert the provided data stream of bytes into a hex string.
 * 
 * @param[in]  begin Beginning of the data stream.
 * @param[in]  end   End point of the data stream.
 * @return     Hex string representing the data stream.
 */
template<typename iter_t>
std::string bytesToHex(iter_t begin, iter_t const& end) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    while (begin != end) {
        hex << std::setw(2) << static_cast<unsigned>(*begin++);
    }
    return hex.str();
}

/**
 * Returns a Result object reference with ResultCode::OK and an empty message string.
 */
const Result& resultOk();

/**
 * Create a new result object with the provided ResultCode. The Result message is attached to the
 * object in a printf-like formatting of the provided arguments.
 *
 * @param[in] code    ResultCode for the result object.
 * @param[in] format  Format string.
 * @param[in] va_list List of arguments attached to the format string.
 */
Result result(ResultCode code, const char* format, ...);

/**
 * Reads the status from the given RespondApdu and converts it into a ResultCode for the HAL
 * interface.
 *
 * @param[in] Response APDU from the applet that should be decoded.
 * @param[in] msgOnError Error message that should be printed if response contains an error message.
 * @return    The corresponding HAL ResultCode.
 */
Result swToErrorMessage(const ResponseApdu& apdu, const std::string& msgOnError);

/**
 * Comparator to sort a list of access control profiles based on their ID.
 */
struct AccessControlComparator {
    bool operator()(const SecureAccessControlProfile& pr1,
                    const SecureAccessControlProfile& pr2) {
        return pr1.id < pr2.id;
    }
};

/**
 * Helper function for CBOR unique pointer.
 */
struct CBOR_Deleter {
    void operator()(cn_cbor* cb) const {
        if (cb != nullptr) {
            cn_cbor_free(cb);
        }
    }
};
using CBORPtr = std::unique_ptr<cn_cbor, CBOR_Deleter>;


/**
 * Encodes the provided CBOR structure as vector of byte values. 
 * 
 * @param[in]   data    CBOR structure that should be encoced.
 * @param[out]  err     Indicates if an error occured during encoding.
 * @return              The encoded vectore.
 */
std::vector<uint8_t> encodeCborAsVector(const cn_cbor* data, cn_cbor_errback* err);

/**
 * Create a CommandAPDU object with the serialized data of the provided cbor object.
 *
 * @param[in]  ins   The instruction byte of the comannd APDU
 * @param[in]  p1    Parameter 1 byte of the comannd APDU
 * @param[in]  p2    Parameter 2 byte of the comannd APDU
 * @param[in]  data  The CBOR object
 * @param[out] err   Indicates if an error occured during encoding
 * @return           The generated Command APDU object
 */
CommandApdu createCommandApduFromCbor(const uint8_t ins, const uint8_t p1, const uint8_t p2, const cn_cbor* data,
                                      cn_cbor_errback* err);

/**
 * Encodes the provided parameters of an access control profile in a CBOR map.
 * AccessControlProfile = {
 *     "id": uint,
 *     ? "readerAuthPubKey" : bstr,
 *     ? (
 *         "userAuthTypes": uint,
 *         "userSecureId" : uint,   ; 64 bits
 *         ? "timeout": uint,
 *     )
 * }
 *
 * @param[in]  profileId         The ID of the profile
 * @param[in]  readerAuthPubKey  Public key of the reader that needs to be authenticed to allow
 *                               requests. Will not be added to the map if size = 0.
 * @param[in]  capabilityId      The secure user ID that must be authenticated to allow requests.
 *                               Will not be addded to CBOR structure if the value is zero.
 * @param[in]  capabilityType    The type of the keymaster capability that is required in user
 *                               authentication
 * @param[in]  timeout           Specifies the amount of time, in seconds, for which a user
 *                               authentication is valid, if capabilityId is non-empty.
 * @return     The generated cbor structure with the access control profile
 */
cn_cbor* encodeCborAccessControlProfile(const uint64_t profileId, const hidl_vec<uint8_t>& readerAuthPubKey,
                                        const uint64_t capabilityId, const CapabilityType capabilityType,
                                        const uint64_t timeout);

/**
 * Encodes a namespace configuration CBOR array.
 * NamespaceConf = [
 *        uint, ; number of entries in namespace
 *        tstr  ; namespace name
 * ]
 *
 * @param[in]  nameSpaceName        Namespace name
 * @param[in]  nameSpaceEntryCount  Number of entries in this namespace
 * @return     The generated cbor structure with the namespace configuration
 */
cn_cbor* encodeCborNamespaceConf(const std::string& nameSpaceName, const uint16_t nameSpaceEntryCount);

/**
 * Encode a boolean (cn-cbor does not support it out of the box)
 * 
 * @param[in]  val Boolean value that shoul be encoded
 * @param[out] err Indicates to the caller if an error occured during encoding
 * @return     The encoded cbor structure with the boolean value
 */
cn_cbor* encodeCborBoolean(const bool val, cn_cbor_errback* err);

/**
 * Encodes the additional data cbor array.
 * AdditionalData = {
 *         "namespace" : tstr,
 *         "name" : tstr,
 *         "accessControlProfileIds" : [ + uint ],
 * }
 *
 * @param[in]  nameSpaceName            Namespace name
 * @param[in]  name                     Name of the entry
 * @param[in]  accessControlProfileIds  Ids that specify the access control profiles that grants
 * access to this entry
 * @return     The generated cbor structure with the additional data information of an entry
 */
cn_cbor* encodeCborAdditionalData(const std::string& nameSpaceName, const std::string& name,
                                  const hidl_vec<uint8_t>& accessControlProfileIds);

/**
 * Decode the first byte of a CBOR structure and return the length of the header.
 * 
 * @param[in]  firstByte    First byte of CBOR structure
 * @return The number of bytes of the CBOR header
 */
uint8_t decodeCborHeaderLength(const uint8_t firstByte);

/**
 * Returns the required length of the provided value in a CBOR structure. 
 * 
 * @param[in]   val  Value which will be encoded in CBOR
 * @return      The number of bytes required to encode the value in CBOR
 */
uint8_t encodedCborLength(const uint64_t val);

/**
 * Computes the SHA256 digest of the provided data vector
 * 
 * @param[in]   data     Byte vector with the data that should be digested
 * @return      The computed digest
 */
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

/**
 * Encodes a given EC private key from |key| to an ASN.1, DER structure (PKCS#8). 
 * 
 * @param[in]   cb_privKey  EC private key 
 * @param[out]  err         Indicates if an error occured during encoding
 * @return EC private key in PKCS#8. Will be an empty object if encoding failed.
 */
hidl_vec<uint8_t> encodeECPrivateKey(const cn_cbor *cb_privKey, cn_cbor_errback* err);

/**
 * Decode the public key of the last certificate in a given certificate chain. 
 * 
 * @param[in]  certificateChain certificates that should be parsed
 * @return     Plain elliptic curve point of the public key
 */
hidl_vec<uint8_t> getECPublicKeyFromCertificate(const std::vector<uint8_t>& certificateChain);

}  // namespace implementation
}  // namespace V1_0
}  // namespace identity_credential
}  // namespace hardware
}  // namespace android
#endif  // ANDROID_HARDWARE_IDENTITY_CREDENTIAL_V1_0_ICUTILS_H