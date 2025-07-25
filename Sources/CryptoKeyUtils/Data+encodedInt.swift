//
//  Data+encodedInt.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 25/06/2025.
//

import Foundation

extension Data {
    var encodedInteger: Data {
        var trimmed = data.drop(while: { $0 == 0 }) // Remove leading zeroes
        if trimmed.first?.isBitSet(mask: 0x80) ?? false { // If MSB = 1, add padding 0x00
            trimmed = Data([0x00] + trimmed)
        }
        if trimmed.isEmpty {
            trimmed = Data([0x00])
        }
        return trimmed
    }
}
