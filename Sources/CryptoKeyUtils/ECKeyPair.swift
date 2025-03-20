//
//  ECKeyPair.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/03/2025.
//

import Foundation
import SwiftExtensions

/*
 Works only with P-256/secp256r1
 */
public struct ECKeyPair {
    let x: Data
    let y: Data
    let d: Data
    
    public init(x: Data, y: Data, d: Data) {
        self.x = x
        self.y = y
        self.d = d
    }
    
    public init(x: [UInt8], y: [UInt8], d: [UInt8]) {
        self.x = Data(x)
        self.y = Data(y)
        self.d = Data(d)
    }

    public init(xHexString: String, yHexString: String, dHexString: String) throws {
        self.x = Data(hexString: xHexString)
        self.y = Data(hexString: yHexString)
        self.d = Data(hexString: dHexString)
    }
    
    public var publicKeyDER: Data {
        // OID for `EC Public Key` + `secp256r1`
        let derHeader: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        ]
        
        var derKey = Data(derHeader)
        
        var keyData = Data([0x04])
        keyData.append(x)
        keyData.append(y)
        
        derKey.append(keyData)
        
        return derKey
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
        publicKeyData.append(x)
        publicKeyData.append(y)
        derKey.append(publicKeyData)
        return derKey
    }
    
    public var publicKeyPEM: String {
        let pemHeader = "-----BEGIN PUBLIC KEY-----\n"
        let pemFooter = "\n-----END PUBLIC KEY-----"
        let base64Key = publicKeyDER.base64EncodedString(options: .lineLength64Characters)
        return pemHeader + base64Key + pemFooter
    }
    
    public var privateKeyPEM: String {
        let pemHeader = "-----BEGIN EC PRIVATE KEY-----\n"
        let pemFooter = "\n-----END EC PRIVATE KEY-----"
        let base64Key = privateKeyDER.base64EncodedString(options: .lineLength64Characters)
        return pemHeader + base64Key + pemFooter
    }
}
