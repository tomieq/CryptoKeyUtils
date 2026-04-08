//
//  CustomTests.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 08/04/2026
//
import Testing
import CryptoKeyUtils

struct CustomTests {
    @Test
    func alignPem() throws {
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErPJyxEu2/oKCrJaaTVTrq39DKJ2X
            cN6W+k8UvGf+Y/lDWNbFitQocabsDUvSN0edHH3UKP5QPTz4cOlyIPMrXQ==
            -----END PUBLIC KEY-----
            """
        let key = try ECPublicKey(pem: pem)
        print(key)
        print(try key.pem(format: .pkcs8))
    }
}

