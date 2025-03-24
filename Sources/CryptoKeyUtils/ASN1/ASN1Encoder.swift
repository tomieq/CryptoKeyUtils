import Foundation

extension ASN1 {
    
    public var data: Data {
        Data(Encoder.encode(self))
    }
    
    enum Encoder {
        static func encode(_ node: ASN1) -> [UInt8] {
            switch node {
            case .boolean(let bool):
                return Tag.boolean.bytes + self.asn1LengthPrefixed(bool.bytes)
            case .integer(let integer):
                return Tag.integer.bytes + self.asn1LengthPrefixed(integer.bytes)
            case .bitString(let bits):
                return Tag.bitString.bytes + self.asn1LengthPrefixed([0x00] + bits.bytes)
            case .octetString(let octet):
                return Tag.octetString.bytes + self.asn1LengthPrefixed(octet.bytes)
            case .null:
                return Tag.null.bytes
            case .objectID(let oid):
                return Tag.objectID.bytes + self.asn1LengthPrefixed(oid.bytes)
            case .sequence(let nodes):
                return Tag.sequence.bytes + self.asn1LengthPrefixed( nodes.reduce(into: Array<UInt8>(), { partialResult, node in
                    partialResult += encode(node)
                }))
            }
        }

        private static func asn1LengthPrefix(_ bytes: [UInt8]) -> [UInt8] {
            if bytes.count >= 0x80 {
                var lengthAsBytes = withUnsafeBytes(of: bytes.count.bigEndian, Array<UInt8>.init)
                while lengthAsBytes.first == 0 { lengthAsBytes.removeFirst() }
                return [0x80 + UInt8(lengthAsBytes.count)] + lengthAsBytes
            } else {
                return [UInt8(bytes.count)]
            }
        }

        private static func asn1LengthPrefixed(_ bytes: [UInt8]) -> [UInt8] {
            self.asn1LengthPrefix(bytes) + bytes
        }
    }
}

extension Data {
    var bytes: [UInt8] {
        var byteArray = [UInt8](repeating: 0, count: self.count)
        self.copyBytes(to: &byteArray, count: self.count)
        return byteArray
    }
}
