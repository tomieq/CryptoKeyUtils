//
//  ECPrivateKey.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/03/2025.
//

import Foundation
import SwiftExtensions

/*
 Works only with P-256/secp256r1
 */
public enum ECPrivateKeyFormat {
    case hexString(x: String, y: String, d: String, curve: ECCurve)
    case jwk(x: String, y: String, d: String, crv: String)
}

public enum ECPrivateKeyError: Error {
    case invalidDerStructure(reason: String)
    case invalidPemStructure(reason: String)
    case unsupportedCurve
    case unsupportedBinaryFormat
}

public struct ECPrivateKey {
    public let publicKey: ECPublicKey
    public let d: Data
    public let curve: ECCurve
    
    public init(x: Data, y: Data, d: Data, curve: ECCurve) {
        self.publicKey = ECPublicKey(x: x, y: y, curve: curve)
        self.d = d
        self.curve = curve
    }
    
    public init(x: [UInt8], y: [UInt8], d: [UInt8], curve: ECCurve) {
        self.publicKey = ECPublicKey(x: x, y: y, curve: curve)
        self.d = Data(d)
        self.curve = curve
    }
    
    public init(_ format: ECPrivateKeyFormat) throws {
        switch format {
        case .hexString(let x, let y, let d, let curve):
            self.publicKey = try ECPublicKey(.hexString(x: x, y: y, curve: curve))
            self.d = Data(hexString: d)
            self.curve = curve
        case .jwk(let x, let y, let d, let crv):
            self.publicKey = try ECPublicKey(.jwk(x: x, y: y, crv: crv))
            self.d = try Base64Decoder.data(base64: d)
            self.curve = try ECCurve(jwk: crv) ?! ECPrivateKeyError.unsupportedCurve
        }
        
    }
    
    public init(der: Data) throws {
        let asn1 = try ASN1(data: der)
        guard let format = Self.guessFormat(asn1: asn1) else {
            throw ECPrivateKeyError.unsupportedBinaryFormat
        }
        print("Detected private key DER format: \(format)")
        switch format {
        case .sec1:
            try self.init(sec1: asn1)
        case .pkcs8:
            try self.init(pkcs8: asn1)
        }
    }
    
    static func guessFormat(asn1: ASN1) -> ECBinaryFormat? {
        guard case .sequence(let elements) = asn1 else {
            return nil
        }
        if (elements[safeRange: 0...4].map { $0.tag }) == [.integer, .octetString, .contextSpecific, .contextSpecific] {
            return .sec1
        }
        if (elements[safeRange: 0...3].map { $0.tag }) == [.integer, .sequence, .octetString] {
            return .pkcs8
        }
        print("Cannot detect DER format, unknown ASN1 sequence: \(elements.map { $0.tag }))")
        return nil
    }
    
    // https://www.ietf.org/rfc/rfc5915.txt
    /*
     ECPrivateKey ::= SEQUENCE {
        version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        privateKey     OCTET STRING,
        parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        publicKey  [1] BIT STRING OPTIONAL
     }
     */
    init(sec1 asn1: ASN1) throws {
        
        guard case .sequence(let elements) = asn1 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard elements.count == 4 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain 4 elements")
        }
        guard case .integer(let version) = elements[0], version.integer == 0x01 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Invalid Version")
        }
        guard case .octetString(let d) = elements[1] else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing private key d")
        }
        guard case .contextSpecific(_, let values) = elements[2], values.count == 1,
              case .objectID(let oidData) = values[0], let oid = OID.decodeOID(data: oidData),
        let curve = ECCurve(oid: oid) else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing invalid OID for AlgorithmIdentifier")
        }
        guard case .contextSpecific(_, let values) = elements[3], values.count == 1,
              case .bitString(let publicData) = values[0], publicData.count == 65 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing public key")
        }
        self.init(x: publicData[1...32], y: publicData[33...64], d: d, curve: curve)
    }
    
    // PKCS#8 https://www.ietf.org/rfc/rfc5208.txt
    /*
     PrivateKeyInfo ::= SEQUENCE {
       version                   Version,
       privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
       privateKey                PrivateKey,
       attributes           [0]  IMPLICIT Attributes OPTIONAL }
     */
    init(pkcs8 asn1: ASN1) throws {
        
        guard case .sequence(let elements) = asn1 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard elements.count > 2 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain at least 3 elements")
        }
        guard case .integer(let version) = elements[0], version.integer == 0x00 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Invalid Version")
        }
        guard case .sequence(let values) = elements[1], values.count == 2,
              case .objectID(let oidData) = values[1], let oid = OID.decodeOID(data: oidData),
        let curve = ECCurve(oid: oid) else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing or invalid OID for AlgorithmIdentifier")
        }
        guard case .octetString(let keyAsnData) = elements[2] else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing Key data")
        }
        let keyAsn = try ASN1(data: keyAsnData)
        guard case .sequence(let elements) = keyAsn else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Expected Key SEQUENCE")
        }
        guard elements.count == 3 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Key SEQUENCE should contain 3 elements")
        }
        guard case .integer(let version) = elements[0], version.integer == 0x01 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Invalid Key Version")
        }
        guard case .octetString(let d) = elements[1] else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing private key d")
        }
        guard case .contextSpecific(_, let values) = elements[2], values.count == 1,
              case .bitString(let publicData) = values[0], publicData.count == 65 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing public key")
        }
        
        publicKey = ECPublicKey(x: publicData[1...32], y: publicData[33...64], curve: curve)
        self.d = d
        self.curve = curve
    }

    public init(pem: String) throws {
        var format: ECBinaryFormat {
            get throws {
                for format in ECBinaryFormat.allCases {
                    if pem.contains(format.pemHeader), pem.contains(format.pemFooter) {
                        return format
                    }
                }
                throw ECPublicKeyError.invalidPemStructure(reason: "Unknown PEM private key header or footer")
            }
        }
        let pemFormat = try format
        print("Detected PEM in format \(pemFormat)")
        let rawPem = pem
            .replacingOccurrences(of: pemFormat.pemHeader, with: "")
            .replacingOccurrences(of: pemFormat.pemFooter, with: "")
            .replacingOccurrences(of: "\n", with: "")
        let der = try Base64Decoder.data(base64: rawPem)
        try self.init(der: der)
    }
    
    public func der(format: ECBinaryFormat) -> Data {
        switch format {
        case .sec1:
            sec1Der
        case .pkcs8:
            pkcs8Der
        }
    }
    
    var sec1Der: Data {
        // 0x04 means that x and y are concatenated
        var publicKeyData = Data([0x04])
        publicKeyData.append(publicKey.x)
        publicKeyData.append(publicKey.y)
    
        return ASN1.sequence([
            .integer(data: Data([0x01])),
            .octetString(data: d),
            .contextSpecific(tag: 0xa0, [.objectID(data: OID.encodeOID(oid: curve.oid)!)]),
            .contextSpecific(tag: 0xa1, [.bitString(data: publicKeyData)])
        ]).data
    }
    
    var pkcs8Der: Data {
        // 0x04 means that x and y are concatenated
        var publicKeyData = Data([0x04])
        publicKeyData.append(publicKey.x)
        publicKeyData.append(publicKey.y)
        
        let privateKey = ASN1.sequence([
            .integer(data: Data([0x01])),
            .octetString(data: d),
            .contextSpecific(tag: 0xa1, [.bitString(data: publicKeyData)])
        ]).data
        return ASN1.sequence([
            .integer(data: Data([0x00])),
            .sequence([
                .objectID(data: OID.ecPublicKey.data!),
                .objectID(data: OID.encodeOID(oid: curve.oid)!)
            ]),
            .octetString(data: privateKey)
        ]).data
    }
    
    public func pem(format: ECBinaryFormat) -> String {
        let base64Key = der(format: format).base64EncodedString(options: .lineLength64Characters)
        return format.pemHeader + "\n" + base64Key + "\n" + format.pemFooter
    }
}
