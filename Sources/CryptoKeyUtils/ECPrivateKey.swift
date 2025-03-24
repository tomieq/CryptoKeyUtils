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
    
    public var privateKeyDER: Data {
        // the ASN.1 structure is hardcoded for P-256/secp256r1 as currently I don't need more
        var derKey = Data([
            0x30, 0x77, 0x02, 0x01,
            0x01, 0x04, 0x20
        ])
        derKey.append(d)
        
        //  P-256
        derKey.append(contentsOf: [
            0xA0, 0x0A,  // [0] EXPLICIT TAG
            0x06, 0x08,  // OBJECT IDENTIFIER (Size 8 bytes)
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07  // 1.2.840.10045.3.1.7 (secp256r1)
        ])
        
        //  `0x04 || X || Y`
        derKey.append(contentsOf: [0xA1, 0x44, 0x03, 0x42, 0x00])
        
        // 0x04 means that x and y are concatenated
        var publicKeyData = Data([0x04])
        publicKeyData.append(publicKey.x)
        publicKeyData.append(publicKey.y)
        derKey.append(publicKeyData)
        return derKey
    }
    
    public var privateKeyPEM: String {
        let pemHeader = "-----BEGIN EC PRIVATE KEY-----\n"
        let pemFooter = "\n-----END EC PRIVATE KEY-----"
        let base64Key = privateKeyDER.base64EncodedString(options: .lineLength64Characters)
        return pemHeader + base64Key + pemFooter
    }
}
