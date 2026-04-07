//
//  RSAPublicKeyFormat.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 07/04/2026
//

public enum RSAPublicKeyFormat: CaseIterable {
    case pkcs1
    case subjectPublicKeyInfo
}

extension RSAPublicKeyFormat {
    var pemHeader: String {
        switch self {
        case .pkcs1:
            "-----BEGIN RSA PUBLIC KEY-----"
        case .subjectPublicKeyInfo:
            "-----BEGIN PUBLIC KEY-----"
        }
    }
    
    var pemFooter: String {
        switch self {
        case .pkcs1:
            "-----END RSA PUBLIC KEY-----"
        case .subjectPublicKeyInfo:
            "-----END PUBLIC KEY-----"
        }
    }
}
