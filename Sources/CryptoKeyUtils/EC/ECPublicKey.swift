//
//  ECPublicKey.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//

import Foundation
import SwiftExtensions
import SwiftyTLV

public enum ECPublicKeyInfo {
    case hexString(x: String, y: String, curve: ECCurve)
    case jwk(x: String, y: String, crv: String)
}

public enum ECPublicKeyError: Error {
    case invalidDerStructure(reason: String)
    case invalidPemStructure(reason: String)
    case unsupportedCurve
}

public struct ECPublicKey: CryptoKey {
    public let x: Data
    public let y: Data
    public let curve: ECCurve

    static let oid = "1.2.840.10045.2.1"
    
    static let pemHeader = "-----BEGIN PUBLIC KEY-----\n"
    static let pemFooter = "\n-----END PUBLIC KEY-----"
    
    public init(x: Data, y: Data, curve: ECCurve) {
        self.x = x
        self.y = y
        self.curve = curve
    }
    
    public init(x: [UInt8], y: [UInt8], curve: ECCurve) {
        self.x = Data(x)
        self.y = Data(y)
        self.curve = curve
    }
    
    public init(_ info: ECPublicKeyInfo) throws {
        switch info {
        case .hexString(let x, let y, let curve):
            self.x = Data(hexString: x)
            self.y = Data(hexString: y)
            self.curve = curve
        case .jwk(let x, let y, let crv):
            self.x = try Base64Decoder.data(base64: x)
            self.y = try Base64Decoder.data(base64: y)
            self.curve = try ECCurve(jwk: crv).orThrow(ECPublicKeyError.unsupportedCurve)
        }
    }
    
    public init(der: Data) throws {
        let asn1 = try der.asn1
        let format = try Self.guessFormat(asn1: asn1).orThrow(RSAPublicKeyError.unsupportedBinaryFormat)
        print("Detected public EC key DER format: \(format)")
        switch format {
        case .pkcs8:
            try self.init(pkcs8: asn1)
        }
    }
    
    public init(pem: String) throws {
        var format: ECPublicKeyFormat {
            get throws {
                for format in ECPublicKeyFormat.allCases {
                    if pem.contains(format.pemHeader), pem.contains(format.pemFooter) {
                        return format
                    }
                }
                throw ECPublicKeyError.invalidPemStructure(reason: "Unknown PEM private key header or footer")
            }
        }
        let pemFormat = try format
        let rawPem = pem
            .removed(text: Self.pemHeader)
            .removed(text: Self.pemFooter)
            .removed(text: "\n")
        let der = try Base64Decoder.data(base64: rawPem)
        switch pemFormat {
        case .pkcs8:
            try self.init(pkcs8: try der.asn1)
        }
    }
    
    private static func guessFormat(asn1: ASN1) -> ECPublicKeyFormat? {
        .pkcs8
    }
    
    /*
     PublicKeyInfo ::= SEQUENCE {
           algorithm   AlgorithmIdentifier,
           PublicKey   BIT STRING
         }
         
         AlgorithmIdentifier ::= SEQUENCE {
           algorithm   OBJECT IDENTIFIER,
           parameters  ANY DEFINED BY algorithm OPTIONAL
         }
     */
    init(pkcs8 asn1: ASN1) throws {
        guard case .sequence(let elements) = asn1 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard case .sequence(let oidList) = elements[safeIndex: 0] else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain SEQUENCE with OBJECTID at index 0")
        }
        guard case .objectIdentifier(let keyTypeOID) = oidList[safeIndex: 0], let keyType = CryptoOID(rawValue: keyTypeOID) else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Expected OBJECTID with key type in SEQUENCE")
        }
        guard keyType == .ecPublicKey else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Currently only EC keys are supported, but found \(keyTypeOID)")
        }
        
        guard case .objectIdentifier(let curveTypeOID) = oidList[safeIndex: 1], let curveType = ECCurve(rawValue: curveTypeOID) else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Expected OBJECTID with curve type in SEQUENCE")
        }
        guard case .bitString(var numbers) = elements[safeIndex: 1], numbers.count == 66 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Expected BITSTRING with x and y values")
        }
        guard try numbers.consume(bytes: 2).uInt16 == 0x04 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Missing 0x04 padding in BITSTRING with x and y values")
        }
        x = Data(numbers.consume(bytes: 32))
        y = Data(numbers.consume(bytes: 32))
        self.curve = curveType
    }
    
}
extension ECPublicKey {
    public func der(format: ECPublicKeyFormat) throws -> Data {
        switch format {
        case .pkcs8:
            try pkcs8der
        }
    }
    
    public func pem(format: ECPublicKeyFormat) throws -> String {
        let base64Key = try der(format: format).base64EncodedString(options: .lineLength64Characters)
        return format.pemHeader + "\n" + base64Key + "\n" + format.pemFooter
    }
}

// PKCS#8
extension ECPublicKey {
    public var pkcs8der: Data {
        get throws {
            try pkcs8asn1.data
        }
    }
    public var pkcs8asn1: ASN1 {
        get throws {
            var keyData = UInt16(4).data
            keyData.append(x)
            keyData.append(y)
            return ASN1.sequence([
                .sequence([
                    .objectIdentifier(CryptoOID.ecPublicKey.rawValue),
                    .objectIdentifier(curve.rawValue)
                ]),
                .bitString(keyData)
            ])
        }
    }
}

extension ECPublicKey: CustomStringConvertible {
    public var description: String {
        "ECPublicKey {\n\tx: \(self.x.hexString)\n\ty: \(self.y.hexString)\n\tcurve: \(self.curve)\n}"
    }
}
