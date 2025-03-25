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
