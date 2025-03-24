
//
//  ECKeyPairTests.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 20/03/2025.
//

import Testing
import Foundation
import CryptoKeyUtils

struct ECKeyPairTests {
    @Test func verifyPublicPem() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECKeyPair(.hexString(x: x, y: y, d: d))

        let publicPEM = key.publicKeyPEM
        print(publicPEM)
        #expect(publicPEM.contains("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFlk7Nn7MULhf/yadlMA9QAFdhIH"))
        #expect(publicPEM.contains("J14nqY9VS7eOkEsuTSfG26BCvTHFMmBJ8kGYpmchPr9h+jGRjp3VNda/ew=="))
    }
    
    @Test func verifyPublicDER() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECKeyPair(.hexString(x: x, y: y, d: d))

        let expectedBinary = "3059301306072A8648CE3D020106082A8648CE3D03010703420004405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        #expect(key.publicKeyDER.hexString == expectedBinary)
        
        let asn1 = try ASN1(data: key.publicKeyDER)
        print(asn1)
    }

    @Test func verifyPrivatePem() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECKeyPair(.hexString(x: x, y: y, d: d))

        let privatePEM = key.privateKeyPEM
        print(privatePEM)
        #expect(privatePEM.contains("MHcCAQEEIFOJMmeobWPRNAAeVpBDb+avsF8EgguliiGXNHyXtSeaoAoGCCqGSM49"))
        #expect(privatePEM.contains("AwEHoUQDQgAEQFlk7Nn7MULhf/yadlMA9QAFdhIHJ14nqY9VS7eOkEsuTSfG26BC"))
        #expect(privatePEM.contains("vTHFMmBJ8kGYpmchPr9h+jGRjp3VNda/ew=="))
    }
    
    @Test func keyFromJWK() throws {
        let d = "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
        let x = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74"
        let y = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
        let key = try ECKeyPair(.jwk(x: x, y: y, d: d))

        let publicPEM = key.publicKeyPEM
        print(publicPEM)
        #expect(publicPEM.contains("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESVqB4JcUD6lsfvqMr+OKUNUphdNn"))
        #expect(publicPEM.contains("64Eay60978ZlL76V/S7SkyPiUYDNmLHm7gKbkIxAiAw2mTDLXrfC0phUog=="))
    }
    
    @Test func testOIDConverter() throws {
        let oid = "1.2.840.10045.4.3.2"
        #expect(OID.decodeOID(data: OID.encodeOID(oid: oid)!) == oid)
    }
}
