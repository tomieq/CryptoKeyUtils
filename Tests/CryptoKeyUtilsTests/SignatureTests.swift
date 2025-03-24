//
//  SignatureTests.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//
import Testing
import CryptoKeyUtils

struct SignatureTests {
    @Test func derGenerator() throws {
        let signature = try Signature(.hexString(r: "1A19BD103D5EA607F6A40C86E4D24938ABBD3FD041A1EDA47D689B263BB5D797",
                                                 s: "EB57F23D543AA1007449292B4A64FB1C131517ADA9AABDF0BD4B03F08D6983E2"))
        let expected = "304502201a19bd103d5ea607f6a40c86e4d24938abbd3fd041a1eda47d689b263bb5d797022100eb57f23d543aa1007449292b4a64fb1c131517ada9aabdf0bd4b03f08d6983e2".uppercased()
        #expect(signature.der.hexString == expected)
        print(try ASN1(data: signature.der))
    }
}
