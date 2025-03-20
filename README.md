# CryptoKeyUtils

Simple library to convert raw `P-256/secp256r1` x, y, d key into `DER` and `PEM` format.

## Usage

#### Create from hex string:
```swift
let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
let key = try ECKeyPair(xHexString: x, yHexString: y, dHexString: d)

let privateKey = key.privatePEM
```

There is also convienient initializer for `[UInt8]` and `Data`.

#### Create from JWK

Key might be distributed in `JWK` format:
```
{
  "kty" : "EC",
  "crv" : "P-256",
  "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
}
```
In that case you can use:
```swift
let d = "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
let x = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74"
let y = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
let key = try ECKeyPair(xJWK: x, yJWK: y, dJWK: d)
```

## OpenSSL commands

#### Using openssl to generate secp256r1 key pair:
```
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
```

#### Key investigation
```
openssl ec -in private.pem -text
```
Sample output:
```
read EC key
Private-Key: (256 bit)
priv:
    a7:8e:70:3f:93:c5:c5:e1:6f:b4:18:96:70:bb:d0:
    eb:a4:9c:7a:27:91:50:55:65:8a:37:cc:94:04:72:
    04:0f
pub:
    04:d1:0a:87:20:b7:90:0a:e6:4f:2d:9a:1d:46:60:
    f7:84:25:ce:c3:2b:7c:40:81:5f:c9:02:54:38:aa:
    29:32:7a:24:24:99:f5:b7:3d:fc:ac:62:3f:44:6b:
    15:a0:6f:aa:27:d6:c2:3c:ed:94:49:be:26:21:87:
    04:e5:50:0c:7c
ASN1 OID: prime256v1
NIST CURVE: P-256
writing EC key
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKeOcD+TxcXhb7QYlnC70OuknHonkVBVZYo3zJQEcgQPoAoGCCqGSM49
AwEHoUQDQgAE0QqHILeQCuZPLZodRmD3hCXOwyt8QIFfyQJUOKopMnokJJn1tz38
rGI/RGsVoG+qJ9bCPO2USb4mIYcE5VAMfA==
-----END EC PRIVATE KEY-----
```
The starting `04` in pub section is just meta data and is not part of `x` nor `y` it should be dropped.

## Swift Package Manager
```swift
import PackageDescription

let package = Package(
    name: "MyServer",
    dependencies: [
        .package(url: "https://github.com/tomieq/CryptoKeyUtils", branch: "master")
    ]
)
```
in the target:
```swift
    targets: [
        .executableTarget(
            name: "AppName",
            dependencies: [
                .product(name: "CryptoKeyUtils", package: "CryptoKeyUtils")
            ])
    ]
```
