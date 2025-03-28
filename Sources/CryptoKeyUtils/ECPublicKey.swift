//
//  ECPublicKey.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//

import Foundation
import SwiftExtensions

/*
 Works only with P-256/secp256r1
 */
public enum ECPublicKeyFormat {
    case hexString(x: String, y: String)
    case jwk(x: String, y: String)
}

public enum ECPublicKeyError: Error {
    case invalidDerStructure(reason: String)
    case invalidPemStructure(reason: String)
}

public struct ECPublicKey {
    public let x: Data
    public let y: Data

    static let pemHeader = "-----BEGIN PUBLIC KEY-----\n"
    static let pemFooter = "\n-----END PUBLIC KEY-----"
    
    public init(x: Data, y: Data) {
        self.x = x
        self.y = y
    }
    
    public init(x: [UInt8], y: [UInt8]) {
        self.x = Data(x)
        self.y = Data(y)
    }
    
    public init(_ format: ECPublicKeyFormat) throws {
        switch format {
        case .hexString(let x, let y):
            self.x = Data(hexString: x)
            self.y = Data(hexString: y)
        case .jwk(let x, let y):
            self.x = try Base64Decoder.data(base64: x)
            self.y = try Base64Decoder.data(base64: y)
        }
    }
    
    public init(der: Data) throws {
        let asn1 = try ASN1(data: der)
        guard case .sequence(let elements) = asn1 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard elements.count == 2 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain 2 elements")
        }
        guard case .sequence(let oids) = elements[0] else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain SEQUENCE with OBJECTID at index 0")
        }
        let oidStrings = try oids.compactMap { asn1 in
            guard case .objectID(let data) = asn1 else {
                throw ECPublicKeyError.invalidDerStructure(reason: "Expected OBJECTID in SEQUENCE")
            }
            return OID.decodeOID(data: data)
        }
        let decodedOIDs = oidStrings.compactMap { OID(rawValue: $0) }
        guard decodedOIDs.contains(.ecPublicKey) else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Missing \(OID.ecPublicKey.rawValue) in OBJECTID")
        }
        guard let curveType = (decodedOIDs.first { $0.isEllipticCurve }) else {
            let unknownOIDs = oidStrings.filter { OID(rawValue: $0).isNil }.joined(separator: ", ")
            throw ECPublicKeyError.invalidDerStructure(reason: "Missing or not supported elliptic curve type OID in OBJECTID (\(unknownOIDs)")
        }
        guard case .bitString(let numbers) = elements[1], numbers.count == 65, numbers[0] == 0x04 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Expected BITSTRING with x and y values")
        }
        x = Data(numbers[1...32])
        y = Data(numbers[33...64])
    }
    
    public init(pem: String) throws {
        guard pem.contains(Self.pemHeader), pem.contains(Self.pemFooter) else {
            throw ECPublicKeyError.invalidPemStructure(reason: "Invalid header or footer")
        }
        let rawPem = pem
            .replacingOccurrences(of: Self.pemHeader, with: "")
            .replacingOccurrences(of: Self.pemFooter, with: "")
            .replacingOccurrences(of: "\n", with: "")
        try self.init(der: Base64Decoder.data(base64: rawPem))
    }
    
    public var der: Data {
        var keyData = Data([0x04])
        keyData.append(x)
        keyData.append(y)

        return ASN1.sequence([
            .sequence([
                .objectID(data: OID.ecPublicKey.data!),
                .objectID(data: OID.prime256v1.data!)
            ]),
            .bitString(data: keyData)
        ]).data
    }
    
    public var pem: String {
        let base64Key = der.base64EncodedString(options: .lineLength64Characters)
        return Self.pemHeader + base64Key + Self.pemFooter
    }
}
