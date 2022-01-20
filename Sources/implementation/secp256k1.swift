//
//  secp256k1.swift
//  GigaBitcoin/secp256k1.swift
//
//  Copyright (c) 2021 GigaBitcoin LLC
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation
import secp256k1_bindings

/// The secp256k1 Elliptic Curve.
public enum secp256k1 {}

/// Flags passed to secp256k1_context_create, secp256k1_context_preallocated_size, and secp256k1_context_preallocated_create.
extension secp256k1 {
    public enum Context: UInt32 {
        case none, sign, verify

        public var rawValue: UInt32 {
            let value: Int32

            switch self {
                case .none: value = SECP256K1_CONTEXT_NONE
                case .sign: value = SECP256K1_CONTEXT_SIGN
                case .verify: value = SECP256K1_CONTEXT_VERIFY
            }

            return UInt32(value)
        }
    }
}

/// Flag to pass to secp256k1_ec_pubkey_serialize.
extension secp256k1 {
    public enum Format: UInt32 {
        case compressed, uncompressed

        public var length: Int {
            switch self {
                case .compressed: return 33
                case .uncompressed: return 65
            }
        }

        public var rawValue: UInt32 {
            let value: Int32

            switch self {
                case .compressed: value = SECP256K1_EC_COMPRESSED
                case .uncompressed: value = SECP256K1_EC_UNCOMPRESSED
            }

            return UInt32(value)
        }
    }
}

/// The secp256k1 Elliptic Curve.
extension secp256k1 {
    /// Signing operations on secp256k1
    public enum Signing {
        /// A Private Key for signing.
        public struct PrivateKey: ECPrivateKey, Equatable {
            /// Generated secp256k1 Signing Key.
            private var baseKey: secp256k1.Signing.PrivateKeyImplementation

            /// The secp256k1 private key object
            var key: SecureBytes {
                baseKey.key
            }

            /// The associated public key for verifying signatures done with this private key.
            ///
            /// - Returns: The associated public key
            public var publicKey: PublicKey {
                PublicKey(baseKey: baseKey.publicKey)
            }

            /// A data representation of the private key
            public var rawRepresentation: Data {
                baseKey.rawRepresentation
            }

            /// Creates a random secp256k1 private key for signing
            public init(format: secp256k1.Format = .compressed) throws {
                baseKey = try secp256k1.Signing.PrivateKeyImplementation(format: format)
            }

            /// Creates a secp256k1 private key for signing from a data representation.
            /// - Parameter data: A raw representation of the key.
            /// - Throws: An error is thrown when the raw representation does not create a private key for signing.
            public init<D: ContiguousBytes>(rawRepresentation data: D, format: secp256k1.Format = .compressed) throws {
                baseKey = try secp256k1.Signing.PrivateKeyImplementation(rawRepresentation: data, format: format)
            }

            public static func == (lhs: secp256k1.Signing.PrivateKey, rhs: secp256k1.Signing.PrivateKey) -> Bool {
                lhs.key == rhs.key
            }
        }

        /// The corresponding public key.
        public struct PublicKey {
            /// Generated secp256k1 public key.
            private var baseKey: secp256k1.Signing.PublicKeyImplementation

            /// The secp256k1 public key object
            var keyBytes: [UInt8] {
                baseKey.keyBytes
            }

            /// A data representation of the public key
            public var rawRepresentation: Data {
                baseKey.rawRepresentation
            }

            /// A key format representation of the public key
            public var format: secp256k1.Format {
                baseKey.format
            }

            /// Generates a secp256k1 public key.
            /// - Parameter baseKey: generated secp256k1 public key.
            fileprivate init(baseKey: secp256k1.Signing.PublicKeyImplementation) {
                self.baseKey = baseKey
            }

            /// Generates a secp256k1 public key from a raw representation.
            /// - Parameter data: A raw representation of the key.
            /// - Throws: An error is thrown when the raw representation does not create a public key.
            public init<D: ContiguousBytes>(rawRepresentation data: D, format: secp256k1.Format) {
                baseKey = secp256k1.Signing.PublicKeyImplementation(rawRepresentation: data, format: format)
            }
        }
    }
}

/// Implementations for signing, we use bindings to libsecp256k1 for these operations.
extension secp256k1.Signing {
    /// Private key for signing implementation
    @usableFromInline struct PrivateKeyImplementation {
        /// Backing private key object
        var _privateKey: SecureBytes

        /// Backing public key object
        @usableFromInline var _publicKey: [UInt8]

        /// Backing public key format
        @usableFromInline let _format: secp256k1.Format

        /// Backing implementation for a public key object
        @usableFromInline var publicKey: secp256k1.Signing.PublicKeyImplementation {
            PublicKeyImplementation(_publicKey, format: _format)
        }

        /// Backing secp256k1 private key object
        var key: SecureBytes {
            _privateKey
        }

        /// A data representation of the backing private key
        @usableFromInline var rawRepresentation: Data {
            Data(_privateKey)
        }

        /// Private key length
        static var byteCount: Int = 2 * secp256k1.CurveDetails.coordinateByteCount

        /// Backing initialization that creates a random secp256k1 private key for signing
        @usableFromInline init(format: secp256k1.Format = .compressed) throws {
            let privateKey = SecureBytes(count: Self.byteCount)
            let pubKey = try secp256k1.Signing.PublicKeyImplementation.generatePublicKey(bytes: privateKey.backing.bytes, format: format)

            // Save
            _privateKey = privateKey
            _publicKey = pubKey
            _format = format
        }

        /// Backing initialization that creates a secp256k1 private key for signing from a data representation.
        /// - Parameter data: A raw representation of the key.
        /// - Throws: An error is thrown when the raw representation does not create a private key for signing.
        init<D: ContiguousBytes>(rawRepresentation data: D, format: secp256k1.Format = .compressed) throws {
            let privateKey = SecureBytes(bytes: data)
            let pubKey = try secp256k1.Signing.PublicKeyImplementation.generatePublicKey(bytes: privateKey.backing.bytes, format: format)

            // Save
            _privateKey = privateKey
            _publicKey = pubKey
            _format = format
        }
    }

    /// Public key for signing implementation
    @usableFromInline struct PublicKeyImplementation {
        /// Implementation public key object
        @usableFromInline let keyBytes: [UInt8]

        /// A data representation of the backing public key
        var rawRepresentation: Data {
            Data(keyBytes)
        }

        /// A key format representation of the backing public key
        @usableFromInline let format: secp256k1.Format

        /// Backing initialization that generates a secp256k1 public key from a raw representation.
        /// - Parameter data: A raw representation of the key.
        @inlinable init<D: ContiguousBytes>(rawRepresentation data: D, format: secp256k1.Format) {
            keyBytes = data.bytes
            self.format = format
        }

        /// Backing initialization that sets the public key from a public key object.
        /// - Parameter keyBytes: a public key object
        init(_ keyBytes: [UInt8], format: secp256k1.Format) {
            self.keyBytes = keyBytes
            self.format = format
        }

        /// Generates a secp256k1 public key from bytes representation.
        /// - Parameter privKey: a private key object
        /// - Returns: a public key object
        /// - Throws: An error is thrown when the bytes does not create a public key. 
        static func generatePublicKey(bytes privKey: [UInt8], format: secp256k1.Format) throws -> [UInt8] {
            guard privKey.count == secp256k1.Signing.PrivateKeyImplementation.byteCount else {
                throw secp256k1Error.incorrectKeySize
            }

            // Initialize context
            guard let context = secp256k1_context_create(secp256k1.Context.sign.rawValue) else {
                throw secp256k1Error.underlyingCryptoError
            }

            // Destroy context after creation
            defer { secp256k1_context_destroy(context) }

            // Setup private and public key variables
            var pubKeyLen = format.length
            var cPubKey = secp256k1_pubkey()
            var pubKey = [UInt8](repeating: 0, count: format.length)

            // Verify the context and keys are setup correctly
            guard secp256k1_context_randomize(context, privKey) == 1,
                  secp256k1_ec_pubkey_create(context, &cPubKey, privKey) == 1,
                  secp256k1_ec_pubkey_serialize(context, &pubKey, &pubKeyLen, &cPubKey, format.rawValue) == 1 else {
                      throw secp256k1Error.underlyingCryptoError
            }

            return pubKey
        }
    }
}

public struct Kit {

    public static func sign(data: Data, privateKey: Data) throws -> Data {
        precondition(data.count > 0, "Data must be non-zero size")
        precondition(privateKey.count > 0, "PrivateKey must be non-zero size")

        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        let status = data.withUnsafeBytes { ptr in
            privateKey.withUnsafeBytes { secp256k1_ecdsa_sign(ctx, signature, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), $0.baseAddress!.assumingMemoryBound(to: UInt8.self), nil, nil) }
        }
        guard status == 1 else { throw SignError.signFailed }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length: size_t = 128
        var der = Data(count: length)
        guard der.withUnsafeMutableBytes({ return secp256k1_ecdsa_signature_serialize_der(ctx, $0.baseAddress!.assumingMemoryBound(to: UInt8.self), &length, normalizedsig) }) == 1 else { throw SignError.noEnoughSpace }
        der.count = length

        return der
    }

    public static func compactSign(_ data: Data, privateKey: Data) throws -> Data {
        precondition(data.count > 0, "Data must be non-zero size")
        precondition(privateKey.count > 0, "PrivateKey must be non-zero size")

        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate() }
        let status = data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
            privateKey.withUnsafeBytes { secp256k1_ecdsa_sign(ctx, signature, ptr, $0, nil, nil) }
        }
        guard status == 1 else { throw SignError.signFailed }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { normalizedsig.deallocate() }
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        let length: size_t = 64
        var compact = Data(count: length)
        guard compact.withUnsafeMutableBytes({ return secp256k1_ecdsa_signature_serialize_compact(ctx, $0, normalizedsig) }) == 1 else { throw SignError.noEnoughSpace }
        compact.count = length

        return compact
    }

    public static func createPublicKey(fromPrivateKeyData privateKeyData: Data, compressed: Bool = false) -> Data {
        precondition(privateKeyData.count > 0, "PrivateKeyData must be non-zero size")
        // Convert Data to byte Array
        let privateKey = privateKeyData.withUnsafeBytes {
            [UInt8](UnsafeBufferPointer(start: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: privateKeyData.count))
        }

        // Create signing context
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        // Create public key from private key
        var c_publicKey: secp256k1_pubkey = secp256k1_pubkey()
        let result = secp256k1_ec_pubkey_create(
                ctx,
                &c_publicKey,
                UnsafePointer<UInt8>(privateKey)
        )

        // Serialise public key data into byte array (see header docs for secp256k1_pubkey)
        let keySize = compressed ? 33 : 65
        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: keySize)
        let outputLen = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        defer {
            output.deallocate()
            outputLen.deallocate()
        }
        outputLen.initialize(to: keySize)
        secp256k1_ec_pubkey_serialize(ctx, output, outputLen, &c_publicKey, UInt32(compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
        let publicKey = [UInt8](UnsafeBufferPointer(start: output, count: keySize))

        return Data(publicKey)
    }


    public static func ellipticSign(_ hash: Data, privateKey: Data) throws -> Data {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        guard var signatureInInternalFormat = encrypter.sign(hash: hash, privateKey: privateKey) else {
            throw SignError.signFailed
        }
        return encrypter.export(signature: &signatureInInternalFormat)
    }

    public static func ellipticIsValid(signature: Data, of hash: Data, publicKey: Data, compressed: Bool) -> Bool {
        guard let recoveredPublicKey = self.ellipticPublicKey(signature: signature, of: hash, compressed: compressed) else { return false }
        return recoveredPublicKey == publicKey
    }

    public static func ellipticPublicKey(signature: Data, of hash: Data, compressed: Bool) -> Data? {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        var signatureInInternalFormat = encrypter.import(signature: signature)
        guard var publicKeyInInternalFormat = encrypter.publicKey(signature: &signatureInInternalFormat, hash: hash) else { return nil }
        return encrypter.export(publicKey: &publicKeyInInternalFormat, compressed: compressed)
    }

}
