//
//  CryptoKeyFactoryTests.swift
//  CryptoKeyUtils
// 
//  Created by: tomieq on 08/04/2026
//
import Testing
import CryptoKeyUtils

struct CryptoKeyFactoryTests {
    @Test
    func rsaPrivKeyPkcs1() throws {
        let pem = """
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
        let key = try CryptoKeyFactory.make(pem: pem)
        print(key)
        #expect(key is RSAPrivateKey)
    }
    
    @Test
    func rsaPrivKeyPkcs8() throws {
        let pem = """
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
        let key = try CryptoKeyFactory.make(pem: pem)
        print(key)
        #expect(key is RSAPrivateKey)
    }
    
    @Test
    func rsaPubKeyPkcs1() throws {
        let pem = """
            -----BEGIN RSA PUBLIC KEY-----
            MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnx
            S30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE=
            -----END RSA PUBLIC KEY-----
            """
        let key = try CryptoKeyFactory.make(pem: pem)
        print(key)
        #expect(key is RSAPublicKey)
    }
    
    @Test
    func rsaPubKeySubjectPublicKeyInfo() throws {
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
            9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
            -----END PUBLIC KEY-----
            """
        let key = try CryptoKeyFactory.make(pem: pem)
        print(key)
        #expect(key is RSAPublicKey)
    }
    
    @Test
    func ecPrivKeySec1() throws {
        let pem = """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIEqT+eRC3V7MI/SUWQD0cLU30uAjUaqSiLPtvKzR4jwKoAoGCCqGSM49
            AwEHoUQDQgAErPJyxEu2/oKCrJaaTVTrq39DKJ2XcN6W+k8UvGf+Y/lDWNbFitQo
            cabsDUvSN0edHH3UKP5QPTz4cOlyIPMrXQ==
            -----END EC PRIVATE KEY-----
            """
        let key = try CryptoKeyFactory.make(pem: pem)
        print(key)
        #expect(key is ECPrivateKey)
    }
    
    @Test
    func ecPrivKeyPkcs8() throws {
        let pem = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSpP55ELdXswj9JRZ
            APRwtTfS4CNRqpKIs+28rNHiPAqhRANCAASs8nLES7b+goKslppNVOurf0MonZdw
            3pb6TxS8Z/5j+UNY1sWK1ChxpuwNS9I3R50cfdQo/lA9PPhw6XIg8ytd
            -----END PRIVATE KEY-----
            """
        let key = try CryptoKeyFactory.make(pem: pem)
        print(key)
        #expect(key is ECPrivateKey)
    }
    
    @Test
    func ecPubKeyPkcs8() throws {
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIfuTD3xCiiDYWxcakhBjW80LYDxS
            1mEovWeuH4yN8WDStxcwQ2TCUmdoXl3xQ0DTuNJmHlkl6Tpk/6gzZQCr8A==
            -----END PUBLIC KEY-----
            """
        let key = try CryptoKeyFactory.make(pem: pem)
        print(key)
        #expect(key is ECPublicKey)
    }
}

