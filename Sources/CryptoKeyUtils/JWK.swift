//
//  JWK.swift
//  WMSServer
// 
//  Created by: tomieq on 07/05/2026
//

public struct JWK: Codable {
    public enum KeyType: String, Codable {
        case ec = "EC"
    }

    public let kty: KeyType?
    public let crv: ECCurve
    public let x: String
    public let y: String
    public let d: String?

    enum CodingKeys: String, CodingKey {
        case kty
        case crv
        case x
        case y
        case d
    }

    public init(kty: KeyType?, crv: ECCurve, x: String, y: String, d: String? = nil) {
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let crvName = try container.decode(String.self, forKey: .crv)

        guard let curve = ECCurve(jwk: crvName) else {
            throw DecodingError.dataCorruptedError(forKey: .crv, in: container, debugDescription: "Unsupported EC curve: \(crvName)")
        }

        self.kty = try container.decodeIfPresent(KeyType.self, forKey: .kty)
        self.crv = curve
        self.x = try container.decode(String.self, forKey: .x)
        self.y = try container.decode(String.self, forKey: .y)
        self.d = try container.decodeIfPresent(String.self, forKey: .d)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(kty, forKey: .kty)
        try container.encode(crv.jwk, forKey: .crv)
        try container.encode(x, forKey: .x)
        try container.encode(y, forKey: .y)
        try container.encodeIfPresent(d, forKey: .d)
    }
}

