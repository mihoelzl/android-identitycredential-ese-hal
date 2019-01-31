# Android Identity Credential HAL Implementation

This is a reference implementation of the Android Identity Credential HAL that uses an applet on the embedded secure element to protect confidentiality of credential keys and integrity of data entries. A reference implementation of an JavaCard applet is also available on [github](https://github.com/mihoelzl/android-identitycredential-applet). The main task of this HAL is to act as proxy between the applet and a caller. Encryption and decryption of data entries as well as the creation of signatures is always performed by the applet. See the HAL documentation in AOSP for details how this encryption and signature creation is done. 

## Open issues
* Handle certificate chain in reader authentication: a reader authentication request might consist of multiple certificate. Only the top certificate contains the public key of the current reader that is used to verify the reader authentication data. However, the public key of the parent certificate should be used to check the access control profile. A proper implementation of this ceritificate handling is missing in this handling. 
* Keymaster certificate chain for the attestation certificate of newly created credential keys: at the moment the applet returns a self-signed attestation certificate. The final version for production should return a certificate that is signed by the keymaster attestation key. It is the task of the HAL to attach the keymaster certificate to this attestation certificate and return it to the caller.
* Implement provisioning of direct access configurations as well as their signing keys.
* Transfer user authentication status information from keymaster to the applet. 
