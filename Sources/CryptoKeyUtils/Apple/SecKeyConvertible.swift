#if canImport(Security)
import Foundation
import Security

public enum SecKeyConversionError: Error {
    case unsupportedCurve(ECCurve)
    case keyCreationFailed(reason: String)
}

public protocol SecKeyConvertible {
    var secKey: SecKey { get throws }
}
#endif