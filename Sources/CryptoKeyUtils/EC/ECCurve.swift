//
//  ECCurve.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/05/2025.
//
import Foundation

public enum ECCurveError: Error {
    case unsupportedPrivateKeyLength(Int)
    case unsupportedPublicKeyLength(Int)
}

public enum ECCurve: String, CaseIterable {
    case secp256r1 = "1.2.840.10045.3.1.7"
    case secp384r1 = "1.3.132.0.34"
    case secp521r1 = "1.3.132.0.35"
    case curve25519 = "1.3.101.110"
    case secp256k1 = "1.3.132.0.10"
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

public extension ECCurve {
    var keySizeInBits: Int {
        switch self {
        case .secp256r1: return 256
        case .secp384r1: return 384
        case .secp521r1: return 521
        case .curve25519: return 256
        case .secp256k1: return 256
        }
    }

    var valueLength: Int {
        switch self {
        case .secp256r1, .secp256k1, .curve25519: return 32
        case .secp384r1: return 48
        case .secp521r1: return 66
        }
    }
}

extension ECCurve {
    static func make(publicX963 data: Data) throws -> ECCurve {
        switch data.count {
        case 65:
            .secp256r1
        case 97:
            .secp384r1
        case 133:
            .secp521r1
        default:
            throw ECCurveError.unsupportedPublicKeyLength(data.count)
        }
    }

    static func make(privateX963 data: Data) throws -> ECCurve {
        switch data.count {
        case 97:
            .secp256r1
        case 145:
            .secp384r1
        case 199:
            .secp521r1
        default:
            throw ECCurveError.unsupportedPrivateKeyLength(data.count)
        }
    }
}
