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
    case hexString(x: String, y: String, d: String)
    case jwk(x: String, y: String, d: String)
}

public enum ECPrivateKeyError: Error {
    case invalidDerStructure(reason: String)
    case invalidPemStructure(reason: String)
}

public struct ECPrivateKey {
    public let publicKey: ECPublicKey
    public let d: Data

    static let pemHeader = "-----BEGIN EC PRIVATE KEY-----\n"
    static let pemFooter = "\n-----END EC PRIVATE KEY-----"
    
    public init(x: Data, y: Data, d: Data) {
        self.publicKey = ECPublicKey(x: x, y: y)
        self.d = d
    }
    
    public init(x: [UInt8], y: [UInt8], d: [UInt8]) {
        self.publicKey = ECPublicKey(x: x, y: y)
        self.d = Data(d)
    }
    
    public init(_ format: ECPrivateKeyFormat) throws {
        switch format {
        case .hexString(let x, let y, let d):
            self.publicKey = try ECPublicKey(.hexString(x: x, y: y))
            self.d = Data(hexString: d)
        case .jwk(let x, let y, let d):
            self.publicKey = try ECPublicKey(.jwk(x: x, y: y))
            self.d = try Base64Decoder.data(base64: d)
        }
        
    }
    
    public init(der: Data) throws {
        let asn1 = try ASN1(data: der)
        
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
              case .objectID(let oidData) = values[0], let oid = OID(data: oidData),
                oid.isEllipticCurve else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing OID")
        }
        guard case .contextSpecific(_, let values) = elements[3], values.count == 1,
              case .bitString(let publicData) = values[0], publicData.count == 65 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing public key")
        }
        
        publicKey = ECPublicKey(x: publicData[1...32], y: publicData[33...64])
        self.d = d
    }

    public init(pem: String) throws {
        guard pem.contains(Self.pemHeader), pem.contains(Self.pemFooter) else {
            throw ECPrivateKeyError.invalidPemStructure(reason: "Invalid header or footer")
        }
        let rawPem = pem
            .replacingOccurrences(of: Self.pemHeader, with: "")
            .replacingOccurrences(of: Self.pemFooter, with: "")
            .replacingOccurrences(of: "\n", with: "")
        let der = try Base64Decoder.data(base64: rawPem)
        try self.init(der: der)
    }
    
    public init(pkcs8Der: Data) throws {
        let asn1 = try ASN1(data: pkcs8Der)
        
        guard case .sequence(let elements) = asn1 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard elements.count == 3 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain 3 elements")
        }
        guard case .integer(let version) = elements[0], version.integer == 0x00 else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Invalid Version")
        }
        guard case .sequence(let values) = elements[1], values.count == 2,
              case .objectID(let oidData) = values[1], let oid = OID(data: oidData),
                oid.isEllipticCurve else {
            throw ECPrivateKeyError.invalidDerStructure(reason: "Missing OID")
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
        
        publicKey = ECPublicKey(x: publicData[1...32], y: publicData[33...64])
        self.d = d
    }
    
    public init(pkcs8Pem: String) throws {
        let pkcs8Header = "-----BEGIN PRIVATE KEY-----"
        let pkcs8Footer = "-----END PRIVATE KEY-----"
        guard pkcs8Pem.contains(pkcs8Header), pkcs8Pem.contains(pkcs8Footer) else {
            throw ECPrivateKeyError.invalidPemStructure(reason: "Invalid header or footer")
        }
        let rawPem = pkcs8Pem
            .replacingOccurrences(of: pkcs8Header, with: "")
            .replacingOccurrences(of: pkcs8Footer, with: "")
            .replacingOccurrences(of: "\n", with: "")
        let der = try Base64Decoder.data(base64: rawPem)
        try self.init(pkcs8Der: der)
    }
    
    public var der: Data {
        // 0x04 means that x and y are concatenated
        var publicKeyData = Data([0x04])
        publicKeyData.append(publicKey.x)
        publicKeyData.append(publicKey.y)
    
        return ASN1.sequence([
            .integer(data: Data([0x01])),
            .octetString(data: d),
            .contextSpecific(tag: 0xa0, [.objectID(data: OID.prime256v1.data!)]),
            .contextSpecific(tag: 0xa1, [.bitString(data: publicKeyData)])
        ]).data
    }
    
    public var pem: String {
        let base64Key = der.base64EncodedString(options: .lineLength64Characters)
        return Self.pemHeader + base64Key + Self.pemFooter
    }
}
