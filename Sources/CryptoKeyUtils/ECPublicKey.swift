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

public struct ECPublicKey {
    public let x: Data
    public let y: Data
    
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
    
    public var der: Data {
        var keyData = Data([0x04])
        keyData.append(x)
        keyData.append(y)

        return ASN1.sequence(nodes: [
            .sequence(nodes: [
                .objectID(data: OID.ecPublicKey.data!),
                .objectID(data: OID.prime256v1.data!)
            ]),
            .bitString(data: keyData)
        ]).data
    }
    
    public var pem: String {
        let pemHeader = "-----BEGIN PUBLIC KEY-----\n"
        let pemFooter = "\n-----END PUBLIC KEY-----"
        let base64Key = der.base64EncodedString(options: .lineLength64Characters)
        return pemHeader + base64Key + pemFooter
    }
}
