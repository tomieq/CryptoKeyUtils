//
//  RSAPrivateKeyFormat.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 07/04/2026
//

public enum RSAPrivateKeyFormat: CaseIterable {
    case pkcs1
    case pkcs8
}

extension RSAPrivateKeyFormat {
    var pemHeader: String {
        switch self {
        case .pkcs1:
            "-----BEGIN RSA PRIVATE KEY-----"
        case .pkcs8:
            "-----BEGIN PRIVATE KEY-----"
        }
    }
    
    var pemFooter: String {
        switch self {
        case .pkcs1:
            "-----END RSA PRIVATE KEY-----"
        case .pkcs8:
            "-----END PRIVATE KEY-----"
        }
    }
}
