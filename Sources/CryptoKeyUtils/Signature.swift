//
//  Signature.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//
import Foundation

public enum SignatureFormat {
    case hexString(r: String, s: String)
    case jwk(r: String, s: String)
}

public struct Signature {
    public let r: Data
    public let s: Data
    
    public init(r: Data, s: Data) {
        self.r = r
        self.s = s
    }
    
    public init(r: [UInt8], s: [UInt8]) {
        self.r = Data(r)
        self.s = Data(s)
    }
    
    public init(_ format: SignatureFormat) throws {
        switch format {
        case .hexString(let r, let s):
            self.r = Data(hexString: r)
            self.s = Data(hexString: s)
        case .jwk(let r, let s):
            self.r = try Base64Decoder.data(base64: r)
            self.s = try Base64Decoder.data(base64: s)
        }
    }
    
    public var der: Data {
        ASN1.sequence([
            .integer(data: ASN1.EncodeInteger(data: r)),
            .integer(data: ASN1.EncodeInteger(data: s))
        ]).data
    }
}
