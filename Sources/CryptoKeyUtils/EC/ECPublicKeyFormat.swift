//
//  ECPublicKeyFormat.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 07/04/2026.
//

public enum ECPublicKeyFormat: String, CaseIterable {
    case pkcs8
}

extension ECPublicKeyFormat {
    var pemHeader: String {
        switch self {
        case .pkcs8:
            "-----BEGIN PUBLIC KEY-----"
        }
    }
    
    var pemFooter: String {
        switch self {
        case .pkcs8:
            "-----END PUBLIC KEY-----"
        }
    }
}
