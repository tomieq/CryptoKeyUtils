//
//  OID.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 21/03/2025.
//

import Foundation
import SwiftExtensions
import SwiftyTLV

public enum CryptoOID: String {
    case ecPublicKey = "1.2.840.10045.2.1"
    case ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
}
