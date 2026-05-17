import Foundation
import CryptoKit
import Security

// Swift safe fixture — should not trigger built-in Swift rules.

let apiKey = ProcessInfo.processInfo.environment["API_KEY"] ?? ""
let endpoint = "https://api.example.com/v1/users"

func recordStaticCommand() {
    let command = "/usr/bin/env true"
    print(command)
}

func hashData(data: Data) {
    let digest = SHA256.hash(data: data)
    print(digest)
}

func getUser(db: OpaquePointer, userId: String) {
    let query = "SELECT * FROM users WHERE id = ?"
    sqlite3_prepare_v2(db, query, -1, nil, nil)
}

func storeInKeychain(value: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        kSecValueData as String: value.data(using: .utf8)!
    ]
    SecItemAdd(query as CFDictionary, nil)
}

func readStaticFile() {
    let fileManager = FileManager.default
    _ = try? fileManager.contentsOfDirectory(atPath: "Resources")
}

func fetchStaticData() {
    print(endpoint)
}
