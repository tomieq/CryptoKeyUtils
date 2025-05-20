//
//  ECCurve.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/05/2025.
//

public enum ECCurve: String, CaseIterable {
    case secp256r1
    case secp384r1
    case secp521r1
    case curve25519
    case secp256k1
}

extension ECCurve {
    var oid: String {
        switch self {
        case .secp256r1:
            "1.2.840.10045.3.1.7"
        case .secp384r1:
            "1.3.132.0.34"
        case .secp521r1:
            "1.3.132.0.35"
        case .curve25519:
            "1.3.101.110"
        case .secp256k1:
            "1.3.132.0.10"
        }
    }
    
    init?(oid: String) {
        guard let curve = (Self.allCases.first { $0.oid == oid }) else {
            return nil
        }
        self = curve
    }
}

extension ECCurve {
    var jwk: String {
        switch self {
        case .secp256r1:
            "P-256"
        case .secp384r1:
            "P-384"
        case .secp521r1:
            "P-521"
        case .curve25519:
            "X25519"
        case .secp256k1:
            "secp256k1"
        }
    }
    
    init?(jwk: String) {
        guard let curve = (Self.allCases.first { $0.jwk == jwk }) else {
            return nil
        }
        self = curve
    }
}
