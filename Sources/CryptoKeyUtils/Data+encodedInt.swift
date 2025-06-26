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
        if trimmed.first! & 0x80 != 0 { // If MSB = 1, add padding 0x00
            trimmed.insert(0x00, at: 0)
        }
        return trimmed
    }
}
