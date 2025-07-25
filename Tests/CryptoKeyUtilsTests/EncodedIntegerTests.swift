//
//  EncodedIntegerTests.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 25/07/2025.
//

import Testing
import SwiftExtensions
@testable import CryptoKeyUtils
import Foundation

struct EncodedIntegerTests {
    @Test
    func example() {
        #expect(Data(hexString: "01").encodedInteger == Data(hexString: "01"))
        #expect(Data(hexString: "7F").encodedInteger == Data(hexString: "7F"))
        #expect(Data(hexString: "80").encodedInteger == Data(hexString: "0080"))
        #expect(Data(hexString: "0080").encodedInteger == Data(hexString: "0080"))
        #expect(Data(hexString: "0001").encodedInteger == Data(hexString: "01"))
        #expect(Data(hexString: "00007F").encodedInteger == Data(hexString: "7F"))
        #expect(Data(hexString: "000080").encodedInteger == Data(hexString: "0080"))
        #expect(Data(hexString: "FF").encodedInteger == Data(hexString: "00FF"))
        #expect(Data(hexString: "00FF").encodedInteger == Data(hexString: "00FF"))
        #expect(Data(hexString: "8122").encodedInteger == Data(hexString: "008122"))
        #expect(Data().encodedInteger == Data(hexString: "00"))
    }
}
