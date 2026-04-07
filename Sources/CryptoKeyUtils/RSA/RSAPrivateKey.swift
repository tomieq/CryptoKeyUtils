//
//  RSAPrivateKey.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 07/04/2026
//
import Foundation
import SwiftExtensions
import SwiftyTLV

public enum RSAPrivateKeyError: Error {
    case invalidPemStructure(reason: String)
    case invalidDerStructure(reason: String)
    case unsupportedBinaryFormat
}

public struct RSAPrivateKey {
    public let publicKey: RSAPublicKey
    public let d: Data // privateExponent
    public let p: Data // prime1
    public let q: Data // prime2
    
    public let exponent1: Data // d mod (p-1)
    public let exponent2: Data // d mod (q-1)
    public let coefficient: Data // (inverse of q) mod p
    
    
    
    public init(pem: String) throws {
        var detectedFormat: RSAPrivateKeyFormat? = nil
        for format in RSAPrivateKeyFormat.allCases {
            if pem.contains(format.pemHeader), pem.contains(format.pemFooter) {
                detectedFormat = format
            }
        }
        
        guard let detectedFormat else {
            throw RSAPrivateKeyError.invalidPemStructure(reason: "Invalid header or footer")
        }
        print("Detected Private RSA Key PEM in format \(detectedFormat)")
        let rawPem = pem
            .removed(text: detectedFormat.pemHeader)
            .removed(text: detectedFormat.pemFooter)
            .removed(text: "\n")
        let der = try Base64Decoder.data(base64: rawPem)
        switch detectedFormat {
        case .pkcs1:
            try self.init(pkcs1: try ASN1(data: der))
        case .pkcs8:
            fatalError()
        }
    }
    
    /*
     RSAPrivateKey ::= SEQUENCE {
       version           INTEGER,
       modulus           INTEGER,  -- n
       publicExponent    INTEGER,  -- e
       privateExponent   INTEGER,  -- d
       prime1            INTEGER,  -- p
       prime2            INTEGER,  -- q
       exponent1         INTEGER,  -- d mod (p-1)
       exponent2         INTEGER,  -- d mod (q-1)
       coefficient       INTEGER   -- (inverse of q) mod p
     }
     */
    init(pkcs1 asn1: ASN1) throws {
        guard case .sequence(let elements) = asn1 else {
            throw RSAPrivateKeyError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        
        guard case .integer(let version) = elements[safeIndex: 0], version == 0x00.data else {
            throw RSAPrivateKeyError.invalidDerStructure(reason: "Invalid Version")
        }
        guard case .integer(let modulus) = elements[safeIndex: 1] else {
            throw RSAPrivateKeyError.invalidDerStructure(reason: "Missing modulus")
        }
        guard case .integer(let publicExponent) = elements[safeIndex: 2] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing publicExponent")
        }
        guard case .integer(let privateExponent) = elements[safeIndex: 3] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing privateExponent")
        }
        guard case .integer(let prime1) = elements[safeIndex: 4] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing prime1")
        }
        guard case .integer(let prime2) = elements[safeIndex: 5] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing prime2")
        }
        guard case .integer(let exponent1) = elements[safeIndex: 6] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing exponent1")
        }
        guard case .integer(let exponent2) = elements[safeIndex: 7] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing exponent2")
        }
        guard case .integer(let coefficient) = elements[safeIndex: 8] else {
            throw RSAPublicKeyError.invalidDerStructure(reason: "Missing coefficient")
        }
        self.publicKey = RSAPublicKey(n: modulus, e: publicExponent)
        self.d = privateExponent
        self.p = prime1
        self.q = prime2
        self.exponent1 = exponent1
        self.exponent2 = exponent2
        self.coefficient = coefficient
    }
}

extension RSAPrivateKey: CustomStringConvertible {
    public var description: String {
        "RSAPrivateKey {\n\tn: \(publicKey.n.hexString)\n\te: \(publicKey.e.hexString)\n\td: \(d.hexString)\n\tp: \(p.hexString)\n\tq: \(q.hexString)\n\texponent1: \(exponent1.hexString)\n\texponent2: \(exponent2.hexString)\n\tcoefficient: \(coefficient.hexString)\n}"
    }
}
