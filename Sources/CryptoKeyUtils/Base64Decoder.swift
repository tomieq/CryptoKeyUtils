//
//  Base64Decoder.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/03/2025.
//
import Foundation

public enum Base64DataError: Error {
    case invalidBase64String
}

public struct Base64Decoder {
    static public func data(base64: String) throws -> Data {
        var base64 = base64
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        while base64.count % 4 != 0 {
            base64.append("=")
        }
        
        guard let data = Data(base64Encoded: base64) else {
            throw Base64DataError.invalidBase64String
        }
        return data
    }
}
