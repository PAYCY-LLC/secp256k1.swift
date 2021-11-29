//
//  Schnorr.swift
//  GigaBitcoin/secp256k1.swift
//
//  Copyright (c) 2021 GigaBitcoin LLC
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import secp256k1_bindings

/*
 TODO:
    Keypair, xonly_pub, sign, and verify
    - https://github.com/bitcoin-core/secp256k1/blob/8fa41201bde8844f79198401c60ec57fa84517e3/src/modules/schnorrsig/tests_impl.h#L844-L878
    - https://github.com/bitcoin-core/secp256k1/blob/8fa41201bde8844f79198401c60ec57fa84517e3/include/secp256k1_schnorrsig.h
    - https://github.com/ACINQ/secp256k1-kmp/pull/32/files/0c208788df416aab1c5fea0a9722c673bf728bcc#diff-9b79d940dbbae9e5bcd285b4a775fda481b2536157275e01284ef70f6406c12f

 Test vectors:
    - https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    - https://github.com/swiftcsv/SwiftCSV
*/



/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension secp256k1.Signing {
    public struct Schnorr: ContiguousBytes, NISTECDSASignature {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        @usableFromInline let keypair: [UInt8]

        @usableFromInline let xonlyPub: [UInt8]

        /// Initializes ECDSASignature from the raw representation.
        /// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
        /// - Throws: If there is a failure with the dataRepresentation count
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 4 * secp256k1.CurveDetails.coordinateByteCount else {
                throw secp256k1Error.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)

            keypair = []
            xonlyPub = []
        }

        /// Initializes ECDSASignature from the data representation.
        /// - Parameter dataRepresentation: A data representation of the key as a collection of contiguous bytes.
        /// - Throws: If there is a failure with the dataRepresentation count
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 4 * secp256k1.CurveDetails.coordinateByteCount else {
                throw secp256k1Error.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation

            keypair = []
            xonlyPub = []
        }

        /// Initializes ECDSASignature from the DER representation.
        /// - Parameter derRepresentation: A DER representation of the key as a collection of contiguous bytes.
        /// - Throws: If there is a failure with parsing the derRepresentation
        public init<D: DataProtocol>(derRepresentation: D) throws {
            // Initialize context
            guard let context = secp256k1_context_create(secp256k1.Context.none.rawValue) else {
                throw secp256k1Error.underlyingCryptoError
            }

            let derSignatureBytes = Array(derRepresentation)
            var signature = secp256k1_ecdsa_signature()

            // Destroy context after creation
            defer { secp256k1_context_destroy(context) }

            guard secp256k1_ecdsa_signature_parse_der(context, &signature, derSignatureBytes, derSignatureBytes.count) == 1 else {
                throw secp256k1Error.underlyingCryptoError
            }

            self.rawRepresentation = Data(bytes: &signature.data, count: MemoryLayout.size(ofValue: signature.data))

            keypair = []
            xonlyPub = []
        }

        /// Invokes the given closure with a buffer pointer covering the raw bytes of the digest.
        /// - Parameter body: A closure that takes a raw buffer pointer to the bytes of the digest and returns the digest.
        /// - Throws: If there is a failure with underlying `withUnsafeBytes`
        /// - Returns: The signature as returned from the body closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// Serialize an ECDSA signature in compact (64 byte) format.
        /// - Throws: If there is a failure parsing signature
        /// - Returns: a 64-byte data representation of the compact serialization
        public func compactRepresentation() throws -> Data {
            // Initialize context
            guard let context = secp256k1_context_create(secp256k1.Context.none.rawValue) else {
                throw secp256k1Error.underlyingCryptoError
            }

            let compactSignatureLength = 64
            var signature = secp256k1_ecdsa_signature()
            var compactSignature = [UInt8](repeating: 0, count: compactSignatureLength)

            // Destroy context after creation
            defer { secp256k1_context_destroy(context) }

            withUnsafeMutableBytes(of: &signature.data) { ptr in
                ptr.copyBytes(from: rawRepresentation.prefix(ptr.count))
            }

            guard secp256k1_ecdsa_signature_serialize_compact(context, &compactSignature, &signature) == 1 else {
                throw secp256k1Error.underlyingCryptoError
            }

            return Data(bytes: &compactSignature, count: compactSignatureLength)
        }

        /// A DER-encoded representation of the signature
        /// - Throws: If there is a failure parsing signature
        /// - Returns: a DER representation of the signature
        public func derRepresentation() throws -> Data {
            // Initialize context
            guard let context = secp256k1_context_create(secp256k1.Context.none.rawValue) else {
                throw secp256k1Error.underlyingCryptoError
            }

            var signature = secp256k1_ecdsa_signature()
            var derSignatureLength = 80
            var derSignature = [UInt8](repeating: 0, count: derSignatureLength)

            // Destroy context after creation
            defer { secp256k1_context_destroy(context) }

            withUnsafeMutableBytes(of: &signature.data) { ptr in
                ptr.copyBytes(from: rawRepresentation.prefix(ptr.count))
            }

            guard secp256k1_ecdsa_signature_serialize_der(context, &derSignature, &derSignatureLength, &signature) == 1 else {
                throw secp256k1Error.underlyingCryptoError
            }

            return Data(bytes: &derSignature, count: derSignatureLength)
        }
    }
}
