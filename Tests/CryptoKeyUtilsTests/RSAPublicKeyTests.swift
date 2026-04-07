//
//  RSAPublicKeyTests.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 07/04/2026
//
import Testing
import CryptoKeyUtils

struct RSAPublicKeyTests {
    @Test
    func subjectPublicKeyInfoFromPem() throws {
        let pemString = """
            -----BEGIN PUBLIC KEY-----
            MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
            9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
            -----END PUBLIC KEY-----
            """
        let key = try RSAPublicKey(pem: pemString)
        #expect(key.n.hexString == "00A8F7E069311610FDD2F70D2D82C89C5117E8FA72D6D3DFF429F38F8A7858678A2ECD4FB7C42E294A5129F14B7D1602F4020A8DB2535A2B7E0AABE3598CEF4301")
        
        let constructedPem = try key.pem(format: .subjectPublicKeyInfo)
        print(key)
        #expect(constructedPem.unifiedNewlines == pemString.unifiedNewlines)
    }
    
    @Test
    func pkcs1FromPem() throws {
        let pemString = """
            -----BEGIN RSA PUBLIC KEY-----
            MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnx
            S30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE=
            -----END RSA PUBLIC KEY-----
            """
        let key = try RSAPublicKey(pem: pemString)
        #expect(key.n.hexString == "00A8F7E069311610FDD2F70D2D82C89C5117E8FA72D6D3DFF429F38F8A7858678A2ECD4FB7C42E294A5129F14B7D1602F4020A8DB2535A2B7E0AABE3598CEF4301")
        
        let constructedPem = try key.pem(format: .pkcs1)
        print(key)
        #expect(constructedPem.unifiedNewlines == pemString.unifiedNewlines)
    }
    
}

fileprivate extension String {
    var unifiedNewlines: String {
        replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
    }
}
