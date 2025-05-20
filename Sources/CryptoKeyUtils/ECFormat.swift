//
//  ECFormat.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/05/2025.
//

public enum ECFormat: String, CaseIterable {
    case sec1
    case pkcs8
}

extension ECFormat {
    var pemHeader: String {
        switch self {
        case .sec1:
            "-----BEGIN EC PRIVATE KEY-----"
        case .pkcs8:
            "-----BEGIN PRIVATE KEY-----"
        }
    }
    
    var pemFooter: String {
        switch self {
        case .sec1:
            "-----END EC PRIVATE KEY-----"
        case .pkcs8:
            "-----END PRIVATE KEY-----"
        }
    }
}
