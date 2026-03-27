
## Table 9: Minimum Elements for Cryptographic Assets [1]

Minimum elements pertaining to cryptographic assets from Punjab National Bank (PNB) CERT-IN CBOM documentation.[^1]


| Cryptographic Element | Description |
| :-- | :-- |
| Asset Type | The name of the cryptographic algorithm or asset. For example, "AES-128-GCM" refers to the AES algorithm with a 128-bit key in Galois/Counter Mode (GCM). |
| Asset Type | Specifies the type of cryptographic asset. For algorithms, the asset type is "algorithm". |
| Algorithms Primitive | Describes the cryptographic primitive. For "SHA512withRSA", the primitive is "signature" as it's used for digital signing. |
| Mode | The operational mode used by the algorithm. For example, "gcm" refers to the Galois/Counter Mode used with AES encryption. |
| Crypto Functions | The cryptographic functions supported by the asset. For example, the functions in the case of "AES-128-GCM" are key generation, encryption, decryption, and authentication tag generation. |
| Classical Security Level | The classical security level represents the security strength of the cryptographic asset in terms of its resistance to attacks using classical (non-quantum) methods. For AES-128, it's 128 bits. |
| OID | The Object Identifier (OID) is a globally unique identifier used to refer to the algorithm. It helps in distinguishing algorithms across different systems. For example, "2.16.840.1.101.3.4.1.6" for AES-128-GCM, "1.2.840.113549.1.1.13" for SHA512with RSA. |
| List | Lists the cryptographic algorithms employed by the quantum device or system, allowing for an assessment of its security capabilities, especially in the context of post-quantum encryption standards. |
| Name | The name of the key, which is a unique identifier for the key used in cryptographic operations. |
| Asset Type | Defines the type of cryptographic asset. For keys, the asset type is typically "key". |
| ID | A unique identifier for the key, such as a key ID or reference number. |
| State | The state of the key, such as whether it is active, revoked, or expired. |
| Size | The size of the key, typically measured in bits. For example, a 128-bit key or a 2048-bit RSA key. |
| Creation Date | The date when the key was created. |
| Activation Date | The date when the key became operational or was first used. |
| Protocols Name | The name of the cryptographic protocol, such as TLS, IPsec, or SSH. [^1] |

## Second Table: Protocols, Certificates [^1]

Additional PNB cryptographic elements for protocols and certificates.[^1]


| Cryptographic Element | Description |
| :-- | :-- |
| Asset Type | Defines the type of cryptographic asset. In this case, it would be a "protocol". |
| Version | The version of the protocol used, such as TLS 1.2 or TLS 1.3. |
| Cipher Suites | The set of cryptographic algorithms and parameters supported by the protocol for tasks like encryption, key exchange, and integrity checking. |
| OID | The Object Identifier (OID) associated with the protocol, identifying its unique specifications. |
| Name | The name of the certificate, typically referring to its subject or the entity it represents (e.g., a website). |
| Asset Type | Defines the type of cryptographic asset. For certificates, the asset type is "certificate". |
| Subject Name | This refers to the Distinguished Name (DN) of the entity that the certificate represents. It typically contains information about the organization, domain name. |
| Issuer Name | The issuer is the Certificate Authority (CA) that issued and signed the certificate. This field contains the DN of the CA that verified and issued the certificate. |
| Not Valid Before | This specifies the date and time from which the certificate is valid. |
| Not Valid After | This specifies the expiration date and time of the certificate. The certificate becomes invalid after this timestamp. |
| Signature Algorithm Reference | This refers to the cryptographic algorithm used to sign the certificate. It provides a reference to the algorithm and its OID (Object Identifier). |
| Subject Public Key Reference | This points to the public key used by the subject (the entity being identified in the certificate). It provides a reference to the key's details, including the algorithm. |
| Certificate Format | Specifies the format of the certificate. Common formats include X.509, which is the most widely used format for certificates. |
| Certificate Extension | This refers to the file extension associated with the certificate. It is commonly .crt for certificates in the X.509 format. [^1] |

<div align="center">⁂</div>

[^1]: Software-Requirement-Specification-SRS-_Hackathon-2026.pdf

