//
//  ECPublicKey.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//

import Foundation
import SwiftExtensions
import SwiftyTLV

public enum ECPublicKeyFormat {
    case hexString(x: String, y: String, curve: ECCurve)
    case jwk(x: String, y: String, crv: String)
}

public enum ECPublicKeyError: Error {
    case invalidDerStructure(reason: String)
    case invalidPemStructure(reason: String)
    case unsupportedCurve
}

public struct ECPublicKey {
    public let x: Data
    public let y: Data
    public let curve: ECCurve

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
    
    public init(_ format: ECPublicKeyFormat) throws {
        switch format {
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
        let asn1 = try ASN1(data: der)
        guard case .sequence(let elements) = asn1 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard elements.count == 2 else {
            throw ECPublicKeyError.invalidDerStructure(reason: "Main SEQUENCE should contain 2 elements")
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
    
    public init(pem: String) throws {
        guard pem.contains(Self.pemHeader), pem.contains(Self.pemFooter) else {
            throw ECPublicKeyError.invalidPemStructure(reason: "Invalid header or footer")
        }
        let rawPem = pem
            .removed(text: Self.pemHeader)
            .removed(text: Self.pemFooter)
            .removed(text: "\n")
        try self.init(der: Base64Decoder.data(base64: rawPem))
    }
    
    public var der: Data {
        get throws {
            var keyData = UInt16(4).data
            keyData.append(x)
            keyData.append(y)
            print(keyData.hexString)
            return try ASN1.sequence([
                .sequence([
                    .objectIdentifier(CryptoOID.ecPublicKey.rawValue),
                    .objectIdentifier(curve.rawValue)
                ]),
                .bitString(keyData)
            ]).data
        }
    }
    
    public var pem: String {
        get throws {
            let base64Key = try der.base64EncodedString(options: .lineLength64Characters)
            return Self.pemHeader + base64Key + Self.pemFooter
        }
    }
}
