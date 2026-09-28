#!/usr/bin/env swift

import CryptoKit
import Darwin
import Foundation

private enum CryptoError: LocalizedError {
    case invalidArguments
    case invalidPrivateKey
    case invalidPublicKey
    case invalidSignature
    case verificationFailed

    var errorDescription: String? {
        switch self {
        case .invalidArguments: return "invalid arguments"
        case .invalidPrivateKey: return "invalid private key file"
        case .invalidPublicKey: return "invalid public key file"
        case .invalidSignature: return "invalid signature"
        case .verificationFailed: return "signature verification failed"
        }
    }
}

private func argument(_ name: String, from arguments: [String]) throws -> URL {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else {
        throw CryptoError.invalidArguments
    }
    return URL(fileURLWithPath: arguments[index + 1])
}

private func regularFile(_ url: URL) throws -> Data {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    guard values.isRegularFile == true, values.isSymbolicLink != true else {
        throw CryptoError.invalidArguments
    }
    return try Data(contentsOf: url)
}

private func privateKey(from url: URL) throws -> Curve25519.Signing.PrivateKey {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard values.isRegularFile == true, values.isSymbolicLink != true,
          let permissions = attributes[.posixPermissions] as? NSNumber,
          permissions.intValue & 0o777 == 0o600,
          let encoded = String(data: try Data(contentsOf: url), encoding: .utf8),
          let raw = Data(base64Encoded: encoded.trimmingCharacters(in: .whitespacesAndNewlines)),
          raw.count == 32
    else { throw CryptoError.invalidPrivateKey }
    return try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
}

private func publicKey(from url: URL) throws -> Curve25519.Signing.PublicKey {
    guard let encoded = String(data: try regularFile(url), encoding: .utf8),
          let raw = Data(base64Encoded: encoded.trimmingCharacters(in: .whitespacesAndNewlines)),
          raw.count == 32
    else { throw CryptoError.invalidPublicKey }
    return try Curve25519.Signing.PublicKey(rawRepresentation: raw)
}

private func write(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: .atomic)
}

private func sign(arguments: [String]) throws {
    let key = try privateKey(from: argument("--private-key-file", from: arguments))
    let input = try regularFile(argument("--input", from: arguments))
    let signature = try key.signature(for: input)
    guard signature.count == 64, key.publicKey.isValidSignature(signature, for: input) else {
        throw CryptoError.verificationFailed
    }
    try write(signature, to: argument("--signature-output", from: arguments))
    try write(Data(key.publicKey.rawRepresentation.base64EncodedString().utf8),
              to: argument("--public-key-output", from: arguments))
}

private func writePublicKey(arguments: [String]) throws {
    let key = try privateKey(from: argument("--private-key-file", from: arguments))
    try write(Data(key.publicKey.rawRepresentation.base64EncodedString().utf8),
              to: argument("--public-key-output", from: arguments))
}

private func verify(arguments: [String]) throws {
    let key = try publicKey(from: argument("--public-key-file", from: arguments))
    let input = try regularFile(argument("--input", from: arguments))
    let signature = try regularFile(argument("--signature", from: arguments))
    guard signature.count == 64 else { throw CryptoError.invalidSignature }
    guard key.isValidSignature(signature, for: input) else { throw CryptoError.verificationFailed }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let command = arguments.first else { throw CryptoError.invalidArguments }
    switch command {
    case "sign": try sign(arguments: Array(arguments.dropFirst()))
    case "public-key": try writePublicKey(arguments: Array(arguments.dropFirst()))
    case "verify": try verify(arguments: Array(arguments.dropFirst()))
    default: throw CryptoError.invalidArguments
    }
} catch {
    FileHandle.standardError.write(Data("offline_grammar_crypto: operation failed\\n".utf8))
    exit(1)
}
