//
//  ECPublicKeyTests.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//


import Testing
import Foundation
import CryptoKeyUtils
import SwiftyTLV

struct ECPublicKeyTests {
    @Test func verifyPublicPem() throws {
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPublicKey(.hexString(x: x, y: y, curve: .secp256r1))

        let publicPEM = try key.pem(format: .pkcs8)
        print(publicPEM)
        #expect(publicPEM.contains("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFlk7Nn7MULhf/yadlMA9QAFdhIH"))
        #expect(publicPEM.contains("J14nqY9VS7eOkEsuTSfG26BCvTHFMmBJ8kGYpmchPr9h+jGRjp3VNda/ew=="))
    }
    
    @Test func verifyPublicDER() throws {
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPublicKey(.hexString(x: x, y: y, curve: .secp256r1))

        let expectedBinary = "3059301306072A8648CE3D020106082A8648CE3D03010703420004405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        #expect(try key.der(format: .pkcs8).hexString == expectedBinary)
        
    }
    
    @Test func keyFromJWK() throws {
        let x = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74"
        let y = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
        let key = try ECPublicKey(jwk: JWK(kty: .ec, crv: .secp256r1, x: x, y: y))

        let publicDER = try key.der(format: .pkcs8)
        let hex = "3059301306072A8648CE3D020106082A8648CE3D03010703420004495A81E097140FA96C7EFA8CAFE38A50D52985D367EB811ACBAD3DEFC6652FBE95FD2ED29323E25180CD98B1E6EE029B908C40880C369930CB5EB7C2D29854A2"
        #expect(publicDER.hexString == hex)
    }
    
    @Test func keyFromSerializedJWK() throws {
        let json = """
        {
          "y" : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
          "x" : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
          "kty" : "EC",
          "crv" : "P-256"
        }
        """
        let key = try ECPublicKey(jwk: JWK(json: json)!)

        let publicDER = try key.der(format: .pkcs8)
        let hex = "3059301306072A8648CE3D020106082A8648CE3D03010703420004495A81E097140FA96C7EFA8CAFE38A50D52985D367EB811ACBAD3DEFC6652FBE95FD2ED29323E25180CD98B1E6EE029B908C40880C369930CB5EB7C2D29854A2"
        #expect(publicDER.hexString == hex)
    }
    
    @Test func keyFromDER() throws {
        let der = Data(hexString: "3059301306072A8648CE3D020106082A8648CE3D03010703420004405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B")
        let key = try ECPublicKey(der: der)
        
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"

        #expect(key.x.hexString == x)
        #expect(key.y.hexString == y)
    }
    
    @Test func keyFromPEM() throws {
        let pem =  """
                    -----BEGIN PUBLIC KEY-----
                    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIfuTD3xCiiDYWxcakhBjW80LYDxS
                    1mEovWeuH4yN8WDStxcwQ2TCUmdoXl3xQ0DTuNJmHlkl6Tpk/6gzZQCr8A==
                    -----END PUBLIC KEY-----
                    """
        let key = try ECPublicKey(pem: pem)
        print(key)
        #expect(key.x.hexString == "21FB930F7C428A20D85B171A9210635BCD0B603C52D66128BD67AE1F8C8DF160")
        #expect(key.y.hexString == "D2B717304364C25267685E5DF14340D3B8D2661E5925E93A64FFA8336500ABF0")
        #expect(key.curve == .secp256r1)
    }
}
