//
//  CryptoKeyFactory.swift
//  CryptoKeyUtils
//
//  Created by: tomieq on 08/04/2026
//
import Foundation
import SwiftyTLV

public enum CryptoKeyFactoryError: Error {
    case invalidPemStructure(reason: String)
    case invalidDerStructure(reason: String)
    case unrecognizedFormat
}

public enum CryptoKeyFactory {
    public static func make(pem: String) throws -> CryptoKey {
        let parts = pem.components(separatedBy: .newlines)
        guard parts.count >= 3 else {
            throw CryptoKeyFactoryError.invalidPemStructure(reason: "PEM string must contain at least 3 lines")
        }
        let body = parts.dropFirst().dropLast().map { String($0) }.joined()
        let der = try Base64Decoder.data(base64: body)
        return try make(der: der)
    }

    public static func make(der: Data) throws -> CryptoKey {
        let asn1 = try ASN1(data: der)
        guard case .sequence(let elements) = asn1 else {
            throw CryptoKeyFactoryError.invalidDerStructure(reason: "Expected opening SEQUENCE")
        }
        
        // RSAPrivateKey pkcs1
        if case .integer = elements[safeIndex: 0],
           case .integer = elements[safeIndex: 1],
           case .integer = elements[safeIndex: 2],
           case .integer = elements[safeIndex: 3],
           case .integer = elements[safeIndex: 4],
           case .integer = elements[safeIndex: 5]
        {
            print("Detected RSAPrivateKey in PKCS#1 format")
            return try RSAPrivateKey(pkcs1: asn1)
        }
        
        // RSAPrivateKey or ECPrivateKey in pkcs8
        if case .integer = elements[safeIndex: 0],
           case .sequence(let algorithm) = elements[safeIndex: 1],
           case .octetString = elements[safeIndex: 2],
           case .objectIdentifier(let oid) = algorithm[safeIndex: 0]
        {
            if oid == RSAPrivateKey.oid {
                print("Detected RSAPrivateKey in PKCS#8 format")
                return try RSAPrivateKey(pkcs8: asn1)
            }
            if oid == ECPrivateKey.oid {
                print("Detected ECPrivateKey in PKCS#8 format")
                return try ECPrivateKey(pkcs8: asn1)
            }
        }
        
        // ECPrivateKey in sec1
        if case .integer = elements[safeIndex: 0],
           case .octetString = elements[safeIndex: 1]
        {
            print("Detected ECPrivateKey in Sec1 format")
            return try ECPrivateKey(sec1: asn1)
        }
        
        // RSAPublicKey pkcs1
        if case .integer = elements[safeIndex: 0],
           case .integer = elements[safeIndex: 1],
           elements.count == 2
        {
            print("Detected RSAPublicKey in PKCS#1 format")
            return try RSAPublicKey(pkcs1: asn1)
        }

        // RSAPublicKey subjectPublicKeyInfo ans ECPublicKey in pkcs#8
        if case .sequence(let algorithm) = elements[safeIndex: 0],
           case .bitString = elements[safeIndex: 1],
           case .objectIdentifier(let oid) = algorithm[safeIndex: 0]
        {
            if oid == RSAPublicKey.oid {
                print("Detected RSAPublicKey in SubjectPublicKeyInfo format")
                return try RSAPublicKey(subjectPublicKeyInfo: asn1)
            }
            if oid == ECPublicKey.oid {
                print("Detected ECPublicKey in PKCS#8 format")
                return try ECPublicKey(pkcs8: asn1)
            }
        }
        print("Unknown format: \(asn1)")
        throw CryptoKeyFactoryError.unrecognizedFormat
        
    }
}

