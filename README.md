# Android Identity Credential HAL Implementation

This is a reference implementation of the Android Identity Credential HAL that uses an applet on the embedded secure element to protect confidentiality of credential keys and integrity of data entries. A reference implementaiton of an JavaCard applet is also available on [github](https://github.com/mihoelzl/android-identitycredential-applet). The main task of this HAL is to act as proxy between the applet and a caller. Encryption and decryption of data entries as well as the creation of signatures is always performed by the applet. See the HAL documentation in AOSP for details how this encryption and signature creation is done. 

Open issues of this HAL:
* Handle certificate chains in reader authentication.
* Keymaster certificate chains for the attestation certificate of newly created credential keys.
* Implement direct access provisioning.
* Transfer user authentication status information from keymaster to the applet. 
 