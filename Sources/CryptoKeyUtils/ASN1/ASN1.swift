//
//  ASN1.swift
//  CryptoKeyUtils
//
//  Created by Tomasz on 21/03/2025.
//

import Foundation
import SwiftExtensions

public enum ASN1: CustomStringConvertible {
    enum Tag: UInt8, Equatable {
        case sequence = 0x30
        case boolean = 0x01
        case integer = 0x02
        case objectID = 0x06
        case null = 0x05
        case bitString = 0x03
        case octetString = 0x04
        
        // class
        case contextSpecific = 0x80
        
        static func == (lhs: UInt8, rhs: Tag) -> Bool {
            lhs == rhs.rawValue
        }
        
        var bytes: [UInt8] {
            switch self {
            case .null:
                return [self.rawValue, 0x00]
            default:
                return [self.rawValue]
            }
        }
    }
    
    case sequence([ASN1])
    case contextSpecific(tag: UInt8, [ASN1])
    case boolean(data: Data)
    case integer(data: Data)
    case objectID(data: Data)
    case null
    case bitString(data: Data)
    case octetString(data: Data)
    
    public var description: String {
        ASN1.printNode(self, level: 0)
    }
    
    
    static func printNode(_ node: ASN1, level: Int) -> String {
        var str: [String] = []
        let prefix = String(repeating: "\t", count: level)
        switch node {
        case .boolean(let bool):
            str.append("\(prefix)Bool: \(bool.hexString)")
        case .integer(let int):
            str.append("\(prefix)Integer: \(int.hexString)")
        case .bitString(let bs):
            str.append("\(prefix)BitString: \(bs.hexString)")
        case .null:
            str.append("\(prefix)NULL")
        case .objectID(let oid):
            var recognisedOID: String {
                if let oid = OID(data: oid) { " (\(oid))" } else { "" }
            }
            str.append("\(prefix)ObjectID: \(OID.decodeOID(data: oid)!) \(recognisedOID)")
        case .octetString(let os):
            str.append("\(prefix)OctetString: \(os.hexString)")
        case .sequence(let nodes):
            str.append("\(prefix)Sequence:")
            nodes.forEach { str.append(printNode($0, level: level + 1)) }
        case .contextSpecific(let tag, let nodes):
            str.append("\(prefix)Context-specific[\(tag.hexString)]:")
            nodes.forEach { str.append(printNode($0, level: level + 1)) }
        }
        return str.joined(separator: "\n")
    }
}
