//
//  ECPrivateKey.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/03/2025.
//

import Foundation
import SwiftExtensions
import SwiftyTLV

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
            self.curve = try ECCurve(jwk: crv).orThrow(ECPrivateKeyError.unsupportedCurve)
        }
        
    }
    
    public init(der: Data) throws {
        let asn1 = try ASN1(data: der)
        let format = try Self.guessFormat(asn1: asn1).orThrow(ECPrivateKeyError.unsupportedBinaryFormat)
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
        if case .integer = elements[safeIndex: 0], case .octetString = elements[safeIndex: 1],
            case .contextSpecificConstructed(tag: 0, _) = elements[safeIndex: 2], case .contextSpecificConstructed(tag: 1, _) = elements[safeIndex: 3]  {
            return .sec1
        }
        if case .integer = elements[safeIndex: 0], case .sequence = elements[safeIndex: 1],
           case .octetString = elements[safeIndex: 2] {
            return .pkcs8
        }
        print("Cannot detect DER format, unknown ASN1 sequence: \(asn1))")
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
        guard case .integer(let version) = elements[safeIndex: 0], version == 0x01.data else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Invalid Version")
        }
        guard case .octetString(let d) = elements[safeIndex: 1] else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing private key d")
        }
        guard case .contextSpecificConstructed(tag: 0, let values) = elements[safeIndex: 2],
              case .objectIdentifier(let oid) = values[safeIndex: 0], let curve = ECCurve(rawValue: oid) else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing or invalid OID for AlgorithmIdentifier")
        }
        guard case .contextSpecificConstructed(tag: 1, let values) = elements[safeIndex: 3],
              case .bitString(var publicData) = values[safeIndex: 0], publicData.count == 66 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing public key")
        }
        guard try publicData.consume(bytes: 2).uInt16 == 0x04 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing 0x04 padding in BITSTRING with x and y values")
        }
        self.init(x: publicData.consume(bytes: 32), y: publicData.consume(bytes: 32), d: d, curve: curve)
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
        
        guard case .sequence(let sequenceElems) = asn1 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard sequenceElems.count > 2 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain at least 3 elements")
        }
        guard case .integer(let version) = sequenceElems[safeIndex: 0], version == 0x00.data else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Invalid Version")
        }
        
        guard case .sequence(let values) = sequenceElems[safeIndex: 1],
              case .objectIdentifier(let oid) = values[safeIndex: 1], let curve = ECCurve(rawValue: oid) else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing or invalid OID for AlgorithmIdentifier")
        }
        guard case .octetString(let keyAsn) = sequenceElems[safeIndex: 2] else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing Key data")
        }
        guard case .sequence(let elements) = try keyAsn.asn1 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Expected Key SEQUENCE")
        }
        guard elements.count == 3 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Key SEQUENCE should contain 3 elements")
        }
        guard case .integer(let version) = elements[safeIndex: 0], version == 0x01.data else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Invalid Key Version")
        }
        guard case .octetString(let d) = elements[safeIndex: 1] else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing private key d")
        }
        guard case .contextSpecificConstructed(_, let values) = elements[safeIndex: 2],
              case .bitString(var publicData) = values[safeIndex: 0], publicData.count == 66 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing public key")
        }
        guard try publicData.consume(bytes: 2).uInt16 == 0x04 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing 0x04 padding in BITSTRING with x and y values")
        }
        publicKey = ECPublicKey(x: publicData.consume(bytes: 32), y: publicData.consume(bytes: 32), curve: curve)
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
            .removed(text: pemFormat.pemHeader)
            .removed(text: pemFormat.pemFooter)
            .removed(text: "\n")
        let der = try Base64Decoder.data(base64: rawPem)
        try self.init(der: der)
    }
    
    public func der(format: ECBinaryFormat) throws -> Data {
        switch format {
        case .sec1:
            try sec1Der
        case .pkcs8:
            try pkcs8Der
        }
    }
    
    var sec1Der: Data {
        get throws {
            // 0x04 means that x and y are concatenated
            var publicKeyData = UInt16(4).data
            publicKeyData.append(publicKey.x)
            publicKeyData.append(publicKey.y)
            
            return try ASN1.sequence([
                .integer(1.data),
                .octetString(d),
                .contextSpecificConstructed(tag: 0, [.objectIdentifier(curve.rawValue)]),
                .contextSpecificConstructed(tag: 1, [.bitString(publicKeyData)])
            ]).data
        }
    }
    
    var pkcs8Der: Data {
        get throws {
            // 0x04 means that x and y are concatenated
            var publicKeyData = UInt16(4).data
            publicKeyData.append(publicKey.x)
            publicKeyData.append(publicKey.y)
            
            let privateKey = try ASN1.sequence([
                .integer(1.data),
                .octetString(d),
                .contextSpecificConstructed(tag: 1, [.bitString(publicKeyData)])
            ]).data
            return try ASN1.sequence([
                .integer(0.data),
                .sequence([
                    .objectIdentifier(CryptoOID.ecPublicKey.rawValue),
                    .objectIdentifier(curve.rawValue)
                ]),
                .octetString(privateKey)
            ]).data
        }
    }
    
    public func pem(format: ECBinaryFormat) throws -> String {
        let base64Key = try der(format: format).base64EncodedString(options: .lineLength64Characters)
        return format.pemHeader + "\n" + base64Key + "\n" + format.pemFooter
    }
}
