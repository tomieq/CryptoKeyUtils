//
//  Optional+operator.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/05/2025.
//

infix operator ?!: NilCoalescingPrecedence

func ?!<T>(value: T?, error: @autoclosure () -> Error) throws -> T {
    guard let value = value else { throw error() }
    return value
}
