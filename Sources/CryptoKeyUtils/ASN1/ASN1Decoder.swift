import Foundation

extension ASN1 {
    
    public init(data: Data) throws {
        self = try Decoder.decode(data: data)
    }

    enum Decoder {
        
        enum DecodingError: Error {
            case noType
            case invalidType(value: UInt8)
        }
        
        static func decode(data: Data) throws -> ASN1 {
            let scanner = ASN1.Scanner(data: data)
            let node = try decodeNode(scanner: scanner)
            return node
        }
        
        private static func decodeNode(scanner: ASN1.Scanner) throws -> ASN1 {
            
            let firstByte = try scanner.consume(length: 1).firstByte
            
            switch firstByte {
            case Tag.sequence.rawValue:
                let length = try scanner.consumeLength()
                let data = try scanner.consume(length: length)
                let nodes = try decodeSequence(data: data)
                return .sequence(nodes: nodes)
                
            case Tag.boolean.rawValue:
                let length = try scanner.consumeLength()
                let data = try scanner.consume(length: length)
                return .boolean(data: data)

            case Tag.integer.rawValue:
                let length = try scanner.consumeLength()
                let data = try scanner.consume(length: length)
                return .integer(data: data)
                
            case Tag.objectID.rawValue:
                let length = try scanner.consumeLength()
                let data = try scanner.consume(length: length)
                return .objectID(data: data)
                
            case Tag.null.rawValue:
                _ = try scanner.consume(length: 1)
                return .null
                
            case Tag.bitString.rawValue:
                let length = try scanner.consumeLength()
                
                // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
                // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
                _ = try scanner.consume(length: 1)
                
                let data = try scanner.consume(length: length - 1)
                return .bitString(data: data)
                
            case Tag.octetString.rawValue:
                let length = try scanner.consumeLength()
                let data = try scanner.consume(length: length)
                return .octetString(data: data)
                
            default:
                print("Unhandled: \(firstByte.hexString)")
                throw DecodingError.invalidType(value: firstByte)
            }
        }
        
        private static func decodeSequence(data: Data) throws -> [ASN1] {
            let scanner = ASN1.Scanner(data: data)
            var nodes: [ASN1] = []
            while !scanner.isComplete {
                let node = try decodeNode(scanner: scanner)
                nodes.append(node)
            }
            return nodes
        }
    }
}
