import Dispatch
import Foundation
import GhostMediaProtocolBridge
import Security

public enum AppleTLSExporter {
    public static func export(
        metadata: sec_protocol_metadata_t,
        context: Data
    ) throws -> DirectionalKeys {
        guard context.count == ProtocolCore.tlsExporterContextLength else {
            throw AppleCryptoError.invalidExporterContextLength(context.count)
        }
        let label = ProtocolCore.tlsExporterLabel
        let exported: dispatch_data_t? = label.withCString { labelPointer in
            context.withUnsafeBytes { contextBytes in
                guard let contextAddress = contextBytes
                    .bindMemory(to: UInt8.self)
                    .baseAddress else {
                    return nil
                }
                return sec_protocol_metadata_create_secret_with_context(
                    metadata,
                    label.utf8.count,
                    labelPointer,
                    contextBytes.count,
                    contextAddress,
                    ProtocolCore.tlsExporterOutputLength
                )
            }
        }
        guard let exported else {
            throw AppleCryptoError.exporterUnavailable
        }

        let dispatchData = DispatchData._unconditionallyBridgeFromObjectiveC(exported)
        let bytes = Data(dispatchData)
        guard bytes.count == ProtocolCore.tlsExporterOutputLength else {
            throw AppleCryptoError.exporterLength(bytes.count)
        }
        return try ProtocolCore.splitExporterOutput(bytes)
    }
}
