import CryptoKit
import Foundation

enum SelfSignedCertificate {
    static func make(
        privateKey: Curve25519.Signing.PrivateKey,
        commonName: String,
        now: Date = Date()
    ) throws -> Data {
        let notBefore = now.addingTimeInterval(-300)
        let algorithm = DER.sequence(DER.oid([1, 3, 101, 112]))
        let name = DER.sequence(
            DER.set(
                DER.sequence(
                    DER.oid([2, 5, 4, 3]),
                    DER.utf8String(commonName)
                )
            )
        )
        let validity = DER.sequence(
            DER.generalizedTime(notBefore),
            DER.generalizedTime(notBefore.addingTimeInterval(825 * 24 * 60 * 60))
        )
        let spki = DER.ed25519SubjectPublicKeyInfo(
            rawPublicKey: privateKey.publicKey.rawRepresentation
        )
        let extensions = DER.explicit(
            tag: 3,
            DER.sequence(
                DER.extensionValue(
                    oid: [2, 5, 29, 19],
                    critical: true,
                    value: DER.sequence()
                ),
                DER.extensionValue(
                    oid: [2, 5, 29, 15],
                    critical: true,
                    value: DER.bitString(Data([0x80]), unusedBits: 7)
                ),
                DER.extensionValue(
                    oid: [2, 5, 29, 37],
                    value: DER.sequence(
                        DER.oid([1, 3, 6, 1, 5, 5, 7, 3, 1]),
                        DER.oid([1, 3, 6, 1, 5, 5, 7, 3, 2])
                    )
                )
            )
        )
        var serial = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        serial[serial.startIndex] &= 0x7f
        if serial.allSatisfy({ $0 == 0 }) {
            serial[serial.startIndex] = 1
        }

        let tbsCertificate = DER.sequence(
            DER.explicit(tag: 0, DER.integer(Data([2]))),
            DER.integer(serial),
            algorithm,
            name,
            validity,
            name,
            spki,
            extensions
        )
        let signature = try privateKey.signature(for: tbsCertificate)
        return DER.sequence(
            tbsCertificate,
            algorithm,
            DER.bitString(signature)
        )
    }
}

enum DER {
    static func sequence(_ values: Data...) -> Data {
        tagged(0x30, values.reduce(into: Data(), { $0.append($1) }))
    }

    static func set(_ values: Data...) -> Data {
        tagged(0x31, values.reduce(into: Data(), { $0.append($1) }))
    }

    static func integer(_ bytes: Data) -> Data {
        var normalized = bytes.drop(while: { $0 == 0 })
        if normalized.isEmpty {
            normalized = Data([0])[...]
        }
        var content = Data(normalized)
        if content[content.startIndex] & 0x80 != 0 {
            content.insert(0, at: content.startIndex)
        }
        return tagged(0x02, content)
    }

    static func oid(_ components: [UInt64]) -> Data {
        precondition(components.count >= 2)
        var encoded = Data([UInt8(components[0] * 40 + components[1])])
        for component in components.dropFirst(2) {
            var value = component
            var groups = [UInt8(value & 0x7f)]
            value >>= 7
            while value != 0 {
                groups.append(UInt8(value & 0x7f) | 0x80)
                value >>= 7
            }
            encoded.append(contentsOf: groups.reversed())
        }
        return tagged(0x06, encoded)
    }

    static func utf8String(_ value: String) -> Data {
        tagged(0x0c, Data(value.utf8))
    }

    static func generalizedTime(_ value: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        return tagged(0x18, Data(formatter.string(from: value).utf8))
    }

    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        var content = Data([unusedBits])
        content.append(value)
        return tagged(0x03, content)
    }

    static func octetString(_ value: Data) -> Data {
        tagged(0x04, value)
    }

    static func boolean(_ value: Bool) -> Data {
        tagged(0x01, Data([value ? 0xff : 0x00]))
    }

    static func explicit(tag: UInt8, _ value: Data) -> Data {
        tagged(0xa0 | tag, value)
    }

    static func extensionValue(
        oid: [UInt64],
        critical: Bool = false,
        value: Data
    ) -> Data {
        if critical {
            return sequence(self.oid(oid), boolean(true), octetString(value))
        }
        return sequence(self.oid(oid), octetString(value))
    }

    static func ed25519SubjectPublicKeyInfo(rawPublicKey: Data) -> Data {
        sequence(
            sequence(oid([1, 3, 101, 112])),
            bitString(rawPublicKey)
        )
    }

    private static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        var output = Data([tag])
        output.append(length(content.count))
        output.append(content)
        return output
    }

    private static func length(_ value: Int) -> Data {
        if value < 128 {
            return Data([UInt8(value)])
        }
        var remaining = value
        var bytes = [UInt8]()
        while remaining != 0 {
            bytes.append(UInt8(remaining & 0xff))
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes.reversed())
    }
}
