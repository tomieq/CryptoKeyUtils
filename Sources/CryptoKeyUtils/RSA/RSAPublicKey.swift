//
//  RSAPublicKey.swift
//  CryptoKeyUtils
//
//  Created by: tomieq on 07/04/2026
//
import Foundation
import SwiftExtensions
import SwiftyTLV


public enum RSAPublicKeyError: Error {
    case invalidPemStructure(reason: String)
    case invalidDerStructure(reason: String)
    case unsupportedBinaryFormat
}

public struct RSAPublicKey {
    public let n: Data // modulus
    public let e: Data // publicExponent
    
    private let oid = "1.2.840.113549.1.1.1"
    
    public init (n: Data, e: Data) {
        self.n = n
        self.e = e
    }
    
    public init(n: [UInt8], e: [UInt8]) {
        self.n = Data(n)
        self.e = Data(e)
    }
    
    public init(pem: String) throws {
        var detectedFormat: RSAPublicKeyFormat? = nil
        for format in RSAPublicKeyFormat.allCases {
            if pem.contains(format.pemHeader), pem.contains(format.pemFooter) {
                detectedFormat = format
            }
        }
        
        guard let detectedFormat else {
            throw RSAPublicKeyError.invalidPemStructure(reason: "Invalid header or footer")
        }
        print("Detected Public RSA Key PEM in format \(detectedFormat)")
        let rawPem = pem
            .removed(text: detectedFormat.pemHeader)
            .removed(text: detectedFormat.pemFooter)
            .removed(text: "\n")
        let der = try Base64Decoder.data(base64: rawPem)
        switch detectedFormat {
        case .pkcs1:
            try self.init(pkcs1: try ASN1(data: der))
        case .subjectPublicKeyInfo:
            try self.init(subjectPublicKeyInfo: try ASN1(data: der))
        }
    }
    
    public init(der: Data) throws {
        let asn1 = try ASN1(data: der)
        let format = try Self.guessFormat(asn1: asn1).orThrow(RSAPublicKeyError.unsupportedBinaryFormat)
        print("Detected public RSA key DER format: \(format)")
        switch format {
        case .pkcs1:
            try self.init(pkcs1: asn1)
        case .subjectPublicKeyInfo:
            try self.init(subjectPublicKeyInfo: asn1)
        }
    }
    
    private static func guessFormat(asn1: ASN1) -> RSAPublicKeyFormat? {
        guard case .sequence(let elements) = asn1 else {
            return nil
        }
        if case .integer = elements[safeIndex: 0], case .integer = elements[safeIndex: 1] {
            return .pkcs1
        }
        if case .sequence = elements[safeIndex: 0], case .sequence = elements[safeIndex: 1] {
            return .subjectPublicKeyInfo
        }
        print("Cannot detect DER format, unknown ASN1 sequence: \(asn1))")
        return nil
    }
    
    /*
     RSAPublicKey ::= SEQUENCE {
     modulus           INTEGER,  -- n
     publicExponent    INTEGER   -- e
     }
     */
    init(pkcs1 asn1: ASN1) throws {
        guard case .sequence(let elements) = asn1 else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard case .integer(let modulus) = elements[safeIndex: 0] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing modulus")
        }
        
        guard case .integer(let publicExponent) = elements[safeIndex: 1] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing publicExponent")
        }
        self.n = modulus
        self.e = publicExponent
    }
    
    /*
     SubjectPublicKeyInfo ::= SEQUENCE {
     algorithm        AlgorithmIdentifier,
     subjectPublicKey BIT STRING
     }
     AlgorithmIdentifier ::= SEQUENCE {
     algorithm   OBJECT IDENTIFIER (rsaEncryption = 1.2.840.113549.1.1.1),
     parameters  NULL
     }
     BITSTRING:
     RSAPublicKey ::= SEQUENCE {
     modulus           INTEGER,
     publicExponent    INTEGER
     }
     */
    init(subjectPublicKeyInfo asn1: ASN1) throws {
        guard case .sequence(let elements) = asn1 else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        guard case .sequence(let values) = elements[safeIndex: 0],
              case .objectIdentifier(let oid) = values[safeIndex: 0] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing OID for AlgorithmIdentifier")
        }
        guard oid == self.oid else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Invalid OID for AlgorithmIdentifier. Expecred \(self.oid), got \(oid)")
        }
        guard case .bitString(var publicKeyData) = elements[safeIndex: 1] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing bitstring with public key")
        }
        if publicKeyData[0] == 0x00 {
            _ = publicKeyData.consume(bytes: 1)
        }
        guard let publicKey = try? ASN1(data: publicKeyData) else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Invalid ASN1 data in bitstring \(asn1)")
        }
        guard case .sequence(let publicKeyElements) = publicKey else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Expected SEQUENCE in bitstring")
        }
        guard case .integer(let modulus) = publicKeyElements[safeIndex: 0] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing modulus")
        }
        
        guard case .integer(let publicExponent) = publicKeyElements[safeIndex: 1] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing publicExponent")
        }
        self.n = modulus
        self.e = publicExponent
    }
}

extension RSAPublicKey {
    
    public func der(format: RSAPublicKeyFormat) throws -> Data {
        switch format {
        case .pkcs1:
            try pkcs1der
        case .subjectPublicKeyInfo:
            try subjectPublicKeyInfoDer
        }
    }
    
    public func pem(format: RSAPublicKeyFormat) throws -> String {
        let base64Key = try der(format: format).base64EncodedString(options: .lineLength64Characters)
        return format.pemHeader + "\n" + base64Key + "\n" + format.pemFooter
    }
}

/// PKCS#1
extension RSAPublicKey {
    public var pkcs1der: Data {
        get throws {
            try pkcs1asn1.data
        }
    }
    
    public var pkcs1asn1: ASN1 {
        get throws {
            return ASN1.sequence([
                .integer(n),
                .integer(e)
            ])
        }
    }
}

/// SubjectPublicKeyInfo
extension RSAPublicKey {
    public var subjectPublicKeyInfoDer: Data {
        get throws {
            try subjectPublicKeyInfoAsn1.data
        }
    }
    
    public var subjectPublicKeyInfoAsn1: ASN1 {
        get throws {
            var publicKeyData = UInt8(0).data
            publicKeyData.append(try self.pkcs1der)
            return ASN1.sequence([
                .sequence([
                    .objectIdentifier(oid),
                    .null
                ]),
                .bitString(publicKeyData)
            ])
        }
    }
}

extension RSAPublicKey: CustomStringConvertible {
    public var description: String {
        "RSAPublicKey {\n\tn: \(n.hexString)\n\te: \(e.hexString))\n}"
    }
}
