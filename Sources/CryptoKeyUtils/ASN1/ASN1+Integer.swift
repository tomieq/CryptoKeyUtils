//
//  ASN1+Integer.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//
import Foundation

extension ASN1 {
    public static func EncodeInteger(data: Data) -> Data {
        var trimmed = data.drop(while: { $0 == 0 }) // Remove leading zeroes
        if trimmed.first! & 0x80 != 0 { // If MSB = 1, add padding 0x00
            trimmed.insert(0x00, at: 0)
        }
        return trimmed
    }
}
