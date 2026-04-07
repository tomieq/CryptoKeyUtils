//
//  RSAPrivateKeyTests.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 07/04/2026
//

import Testing
import CryptoKeyUtils

struct RSAPrivateKeyTests {
    @Test
    func pkcs1Pem() throws {
        let pemString = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
            KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
            o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
            TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
            9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
            v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
            /5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
            -----END RSA PRIVATE KEY-----
            """
        
        let key = try RSAPrivateKey(pem: pemString)
        print(key)
        let constructedPem = try key.pem(format: .pkcs1)
        #expect(constructedPem.unifiedNewlines == pemString.unifiedNewlines)
    }
    
    @Test
    func pkcs8Pem() throws {
        let pemString = """
            -----BEGIN PRIVATE KEY-----
            MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqPfgaTEWEP3S9w0t
            gsicURfo+nLW09/0KfOPinhYZ4ouzU+3xC4pSlEp8Ut9FgL0AgqNslNaK34Kq+NZ
            jO9DAQIDAQABAkAgkuLEHLaqkWhLgNKagSajeobLS3rPT0Agm0f7k55FXVt743hw
            Ngkp98bMNrzy9AQ1mJGbQZGrpr4c8ZAx3aRNAiEAoxK/MgGeeLui385KJ7ZOYktj
            hLBNAB69fKwTZFsUNh0CIQEJQRpFCcydunv2bENcN/oBTRw39E8GNv2pIcNxZkcb
            NQIgbYSzn3Py6AasNj6nEtCfB+i1p3F35TK/87DlPSrmAgkCIQDJLhFoj1gbwRbH
            /bDRPrtlRUDDx44wHoEhSDRdy77eiQIgE6z/k6I+ChN1LLttwX0galITxmAYrOBh
            BVl433tgTTQ=
            -----END PRIVATE KEY-----
            """
        
        let key = try RSAPrivateKey(pem: pemString)
        print(key)
        let constructedPem = try key.pem(format: .pkcs8)
        #expect(constructedPem.unifiedNewlines == pemString.unifiedNewlines)
    }
}

fileprivate extension String {
    var unifiedNewlines: String {
        replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
    }
}
