//
//  OID.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 21/03/2025.
//

import Foundation
import SwiftExtensions

public enum OID: String {
    case prime256v1 = "1.2.840.10045.3.1.7"
    case ecPublicKey = "1.2.840.10045.2.1"
    case ecdsaWithSHA256 = "1.2.840.10045.4.3.2"

    public init?(data: Data) {
        if let decodedOID = OID.decodeOID(data: data), let oid = OID(rawValue: decodedOID) {
            self = oid
        } else {
            return nil
        }
    }
    
    public var data: Data? {
        Self.encodeOID(oid: rawValue)
    }
    
    public static func decodeOID(data: Data) -> String? {
        guard data.isEmpty.not else {
            return nil
        }

        var oid: String = ""
        var data = data
        let first = Int(data.remove(at: 0))
        oid.append("\(first / 40).\(first % 40)")

        var t = 0
        while data.count > 0 {
            let n = Int(data.remove(at: 0))
            t = (t << 7) | (n & 0x7F)
            if (n & 0x80) == 0 {
                oid.append(".\(t)")
                t = 0
            }
        }
        return oid
    }
    
    public static func encodeOID(oid: String) -> Data? {
        let components = oid.split(separator: ".").compactMap { Int($0) }
        guard components.count >= 2 else { return nil }
        
        var data = Data()
        data.append(UInt8(components[0] * 40 + components[1]))
        
        for value in components.dropFirst(2) {
            var bytes: [UInt8] = []
            var v = value
            repeat {
                bytes.insert(UInt8(v & 0x7F) | (bytes.isEmpty ? 0 : 0x80), at: 0)
                v >>= 7
            } while v > 0
            
            data.append(contentsOf: bytes)
        }
        
        return data
    }
    
    static func description(of value: String) -> String? {
        guard let oid = OID(rawValue: value) else {
            return nil
        }
        return "\(oid)"
    }
}
