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
}

fileprivate extension String {
    var unifiedNewlines: String {
        replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
    }
}
