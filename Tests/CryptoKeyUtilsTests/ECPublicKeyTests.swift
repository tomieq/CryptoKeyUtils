//
//  ECPublicKeyTests.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 24/03/2025.
//


import Testing
import Foundation
import CryptoKeyUtils

struct ECPublicKeyTests {
    @Test func verifyPublicPem() throws {
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPublicKey(.hexString(x: x, y: y, curve: .secp256r1))

        let publicPEM = key.pem
        print(publicPEM)
        #expect(publicPEM.contains("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFlk7Nn7MULhf/yadlMA9QAFdhIH"))
        #expect(publicPEM.contains("J14nqY9VS7eOkEsuTSfG26BCvTHFMmBJ8kGYpmchPr9h+jGRjp3VNda/ew=="))
    }
    
    @Test func verifyPublicDER() throws {
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPublicKey(.hexString(x: x, y: y, curve: .secp256r1))

        let expectedBinary = "3059301306072A8648CE3D020106082A8648CE3D03010703420004405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        #expect(key.der.hexString == expectedBinary)
        
        let asn1 = try ASN1(data: key.der)
        print(asn1)
    }
    
    @Test func keyFromJWK() throws {
        let x = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74"
        let y = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
        let key = try ECPublicKey(.jwk(x: x, y: y, crv: "P-256"))

        let publicDER = key.der
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
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFlk7Nn7MULhf/yadlMA9QAFdhIH
        J14nqY9VS7eOkEsuTSfG26BCvTHFMmBJ8kGYpmchPr9h+jGRjp3VNda/ew==
        -----END PUBLIC KEY-----
        """
        let key = try ECPublicKey(pem: pem)
        
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"

        #expect(key.x.hexString == x)
        #expect(key.y.hexString == y)
    }
}
