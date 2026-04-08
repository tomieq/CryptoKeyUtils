//
//  CryptoKey.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 08/04/2026
//
import Foundation

protocol CryptoKey: CustomStringConvertible {
    init(der: Data) throws
    init(pem: String) throws
}

