
//
//  ECKeyPairTests.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/03/2025.
//

import Testing
import Foundation
import CryptoKeyUtils
import SwiftyTLV

struct ECPrivateKeyTests {
    @Test func verifyPublicPem() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPrivateKey(.hexString(x: x, y: y, d: d, curve: .secp256r1))

        let publicPEM = try key.publicKey.pem
        print(publicPEM)
        #expect(publicPEM.contains("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFlk7Nn7MULhf/yadlMA9QAFdhIH"))
        #expect(publicPEM.contains("J14nqY9VS7eOkEsuTSfG26BCvTHFMmBJ8kGYpmchPr9h+jGRjp3VNda/ew=="))
    }
    
    @Test func verifyPublicDER() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPrivateKey(.hexString(x: x, y: y, d: d, curve: .secp256r1))

        let expectedBinary = "3059301306072A8648CE3D020106082A8648CE3D03010703420004405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        #expect(try key.publicKey.der.hexString == expectedBinary)
    }

    @Test func verifyPrivatePem() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPrivateKey(.hexString(x: x, y: y, d: d, curve: .secp256r1))

        let privatePEM = try key.pem(format: .sec1)
        print(privatePEM)
        #expect(privatePEM.contains("MHcCAQEEIFOJMmeobWPRNAAeVpBDb+avsF8EgguliiGXNHyXtSeaoAoGCCqGSM49"))
        #expect(privatePEM.contains("AwEHoUQDQgAEQFlk7Nn7MULhf/yadlMA9QAFdhIHJ14nqY9VS7eOkEsuTSfG26BC"))
        #expect(privatePEM.contains("vTHFMmBJ8kGYpmchPr9h+jGRjp3VNda/ew=="))
    }
    
    @Test func verifyPrivateDer() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPrivateKey(.hexString(x: x, y: y, d: d, curve: .secp256r1))

        let expected = "3077020101042053893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279AA00A06082A8648CE3D030107A14403420004405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let privateDer = try key.der(format: .sec1)
        #expect(privateDer.hexString == expected)
    }
    
    @Test func keyFromJWK() throws {
        let d = "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
        let x = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74"
        let y = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
        let key = try ECPrivateKey(.jwk(x: x, y: y, d: d, crv: "P-256"))

        let publicDER = try key.publicKey.der
        let hex = "3059301306072A8648CE3D020106082A8648CE3D03010703420004495A81E097140FA96C7EFA8CAFE38A50D52985D367EB811ACBAD3DEFC6652FBE95FD2ED29323E25180CD98B1E6EE029B908C40880C369930CB5EB7C2D29854A2"
        #expect(publicDER.hexString == hex)
    }
    
    @Test func keyFromDer() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"

        let der = "3077020101042053893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279AA00A06082A8648CE3D030107A14403420004405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        
        print(try ASN1(data: der.data))
        let key = try ECPrivateKey(der: Data(hexString: der))
        #expect(key.d.hexString == d)
        #expect(key.publicKey.x.hexString == x)
        #expect(key.publicKey.y.hexString == y)
        #expect(key.curve == .secp256r1)
        #expect(key.publicKey.curve == .secp256r1)
    }
    
    @Test func pkcs8() throws {
        let rawPem = """
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSpP55ELdXswj9JRZ
        APRwtTfS4CNRqpKIs+28rNHiPAqhRANCAASs8nLES7b+goKslppNVOurf0MonZdw
        3pb6TxS8Z/5j+UNY1sWK1ChxpuwNS9I3R50cfdQo/lA9PPhw6XIg8ytd
        -----END PRIVATE KEY-----
        """
        
        let hex = "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B02010104204A93F9E442DD5ECC23F4945900F470B537D2E02351AA9288B3EDBCACD1E23C0AA14403420004ACF272C44BB6FE8282AC969A4D54EBAB7F43289D9770DE96FA4F14BC67FE63F94358D6C58AD42871A6EC0D4BD237479D1C7DD428FE503D3CF870E97220F32B5D"
        print(try ASN1(data: hex.data))
        let key = try ECPrivateKey(pem: rawPem)
        #expect(key.d.hexString == "4A93F9E442DD5ECC23F4945900F470B537D2E02351AA9288B3EDBCACD1E23C0A")
        #expect(key.publicKey.x.hexString == "ACF272C44BB6FE8282AC969A4D54EBAB7F43289D9770DE96FA4F14BC67FE63F9")
        #expect(key.publicKey.y.hexString == "4358D6C58AD42871A6EC0D4BD237479D1C7DD428FE503D3CF870E97220F32B5D")
        #expect(key.curve == .secp256r1)
        #expect(try key.der(format: .pkcs8).hexString == hex)
    }
}
