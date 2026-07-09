import CryptoKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Touch ID Authentication

let authenticationCacheWindow: TimeInterval = 60
let authenticationCacheSecretService = "keychain-fingerprint.internal"
let authenticationCacheSecretAccount = "auth-cache-signing-key"

struct AuthenticationCacheEntry: Codable {
    let timestamp: Int64
    let signature: String
}

func authenticationCacheURL() -> URL {
    FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(
            "Library/Caches/keychain-fingerprint",
            isDirectory: true
        )
        .appendingPathComponent("auth-cache.json")
}

func authenticationCacheSecretQuery() -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: authenticationCacheSecretService,
        kSecAttrAccount as String: authenticationCacheSecretAccount,
    ]
}

func generateAuthenticationCacheSecret(length: Int = 32) -> Data? {
    var bytes = [UInt8](repeating: 0, count: length)
    let status = bytes.withUnsafeMutableBytes { buffer in
        SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }

    guard status == errSecSuccess else {
        fputs(
            "Warning: Failed to generate authentication cache secret (status: \(status))\n",
            stderr
        )
        return nil
    }

    return Data(bytes)
}

func getAuthenticationCacheSigningKey() -> SymmetricKey? {
    let query = authenticationCacheSecretQuery().merging([
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]) { _, newValue in
        newValue
    }

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data {
        return SymmetricKey(data: data)
    }

    if status != errSecItemNotFound {
        fputs(
            "Warning: Failed to read authentication cache secret (status: \(status))\n",
            stderr
        )
        return nil
    }

    guard let secretData = generateAuthenticationCacheSecret() else {
        return nil
    }

    let addQuery = authenticationCacheSecretQuery().merging([
        kSecValueData as String: secretData,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]) { _, newValue in
        newValue
    }

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus == errSecSuccess {
        return SymmetricKey(data: secretData)
    }

    if addStatus == errSecDuplicateItem {
        return getAuthenticationCacheSigningKey()
    }

    fputs(
        "Warning: Failed to save authentication cache secret (status: \(addStatus))\n",
        stderr
    )
    return nil
}

func authenticationCacheSignature(
    for cacheKey: String,
    timestamp: Int64,
    using signingKey: SymmetricKey
) -> String {
    let payload = Data("\(cacheKey)\n\(timestamp)".utf8)
    let signature = HMAC<SHA256>.authenticationCode(for: payload, using: signingKey)
    return Data(signature).base64EncodedString()
}

func loadAuthenticationCache(now: Date = Date()) -> [String: Int64] {
    guard let signingKey = getAuthenticationCacheSigningKey() else {
        return [:]
    }

    let url = authenticationCacheURL()
    guard let data = try? Data(contentsOf: url),
        let cache = try? JSONDecoder().decode(
            [String: AuthenticationCacheEntry].self,
            from: data
        )
    else {
        return [:]
    }

    let cutoff = Int64(now.timeIntervalSince1970 - authenticationCacheWindow)
    var verifiedCache: [String: Int64] = [:]

    for (cacheKey, entry) in cache {
        let expectedSignature = authenticationCacheSignature(
            for: cacheKey,
            timestamp: entry.timestamp,
            using: signingKey
        )

        guard entry.signature == expectedSignature, entry.timestamp >= cutoff else {
            continue
        }

        verifiedCache[cacheKey] = entry.timestamp
    }

    return verifiedCache
}

func saveAuthenticationCache(_ cache: [String: Int64]) {
    guard let signingKey = getAuthenticationCacheSigningKey() else {
        return
    }

    let fileManager = FileManager.default
    let url = authenticationCacheURL()
    let directoryURL = url.deletingLastPathComponent()

    var signedCache: [String: AuthenticationCacheEntry] = [:]
    for (cacheKey, timestamp) in cache {
        signedCache[cacheKey] = AuthenticationCacheEntry(
            timestamp: timestamp,
            signature: authenticationCacheSignature(
                for: cacheKey,
                timestamp: timestamp,
                using: signingKey
            )
        )
    }

    do {
        try fileManager.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        let data = try JSONEncoder().encode(signedCache)
        try data.write(to: url, options: .atomic)
        try fileManager.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    } catch {
        fputs(
            "Warning: Failed to update authentication cache: \(error.localizedDescription)\n",
            stderr
        )
    }
}

func hasRecentAuthentication(for cacheKey: String, now: Date = Date()) -> Bool {
    let cache = loadAuthenticationCache(now: now)
    return cache[cacheKey].map {
        TimeInterval($0) >= now.timeIntervalSince1970 - authenticationCacheWindow
    } ?? false
}

func rememberAuthentication(for cacheKey: String, now: Date = Date()) {
    var cache = loadAuthenticationCache(now: now)
    cache[cacheKey] = Int64(now.timeIntervalSince1970)
    saveAuthenticationCache(cache)
}

func authenticateWithTouchID(reason: String, cacheKey: String) -> Bool {
    if hasRecentAuthentication(for: cacheKey) {
        return true
    }

    let context = LAContext()
    var error: NSError?

    // Allow password fallback
    context.localizedFallbackTitle = "Enter Password"

    // Check if Authentication is available
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    else {
        if let error = error {
            fputs(
                "Authentication not available: \(error.localizedDescription)\n",
                stderr
            )
        }
        return false
    }

    let semaphore = DispatchSemaphore(value: 0)
    var success = false

    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
    { result, authError in
        success = result
        if let authError = authError {
            fputs(
                "Authentication failed: \(authError.localizedDescription)\n",
                stderr
            )
        }
        semaphore.signal()
    }

    semaphore.wait()

    if success {
        rememberAuthentication(for: cacheKey)
    }

    return success
}

func isInternalKeychainItem(service: String, account: String) -> Bool {
    service == authenticationCacheSecretService
        && account == authenticationCacheSecretAccount
}

// MARK: - Keychain Operations

func getKeychainPassword(service: String, account: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status == errSecSuccess, let data = result as? Data {
        return String(data: data, encoding: .utf8)
    } else if status == errSecItemNotFound {
        fputs("Error: Password not found\n", stderr)
    } else if status == errSecAuthFailed {
        fputs("Error: Authentication failed\n", stderr)
    } else {
        fputs("Error: Keychain error (status: \(status))\n", stderr)
    }

    return nil
}

func setKeychainPassword(service: String, account: String, password: String)
    -> Bool
{
    // First, try to delete existing item
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    // Add new item (without Access Control - requires paid Developer Program)
    // Security is provided at app level via Touch ID authentication
    guard let passwordData = password.data(using: .utf8) else {
        fputs("Error: Failed to encode password\n", stderr)
        return false
    }

    let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: passwordData,
        kSecAttrAccessible as String:
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]

    let status = SecItemAdd(addQuery as CFDictionary, nil)

    if status != errSecSuccess {
        fputs("Error: Failed to save password (status: \(status))\n", stderr)
        return false
    }

    return true
}

func deleteKeychainPassword(service: String, account: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]

    let status = SecItemDelete(query as CFDictionary)

    if status == errSecSuccess || status == errSecItemNotFound {
        return true
    }

    fputs("Error: Failed to delete password (status: \(status))\n", stderr)
    return false
}

func listKeychainItems(service: String? = nil) -> [(
    service: String, account: String
)] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]

    if let service = service {
        query[kSecAttrService as String] = service
    }

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    var items: [(service: String, account: String)] = []

    if status == errSecSuccess, let itemList = result as? [[String: Any]] {
        for item in itemList {
            if let service = item[kSecAttrService as String] as? String,
                let account = item[kSecAttrAccount as String] as? String,
                !isInternalKeychainItem(service: service, account: account)
            {
                items.append((service: service, account: account))
            }
        }
    }

    return items
}

// MARK: - Secure Input

func readSecurePassword() -> String? {
    // Disable echo for secure input
    var oldTermios = termios()
    tcgetattr(FileHandle.standardInput.fileDescriptor, &oldTermios)

    var newTermios = oldTermios
    newTermios.c_lflag &= ~UInt(ECHO)
    tcsetattr(FileHandle.standardInput.fileDescriptor, TCSANOW, &newTermios)

    defer {
        // Restore echo
        tcsetattr(FileHandle.standardInput.fileDescriptor, TCSANOW, &oldTermios)
        print("")  // New line after hidden input
    }

    return readLine()
}

// MARK: - Main

func printUsage() {
    fputs(
        """
        Usage: keychain-fingerprint <command> [options]

        Commands:
          get <service> <account>     Get password (requires Touch ID)
          set <service> <account>     Set password (requires Touch ID)
          delete <service> <account>  Delete password (requires Touch ID)
          list [service]              List items (requires Touch ID)

        Security:
          - All commands require Touch ID authentication
          - Passwords stored in macOS Keychain (encrypted)
          - Password input is hidden (no echo)
          - Other apps require Mac password to access

        Examples:
          keychain-fingerprint get myapp user@example.com
          keychain-fingerprint set myapp user@example.com
          keychain-fingerprint list
          keychain-fingerprint delete myapp user@example.com

        Shell variable usage:
          PASSWORD=$(keychain-fingerprint get myapp user@example.com)
          # use $PASSWORD
          unset PASSWORD
        """,
        stderr
    )
}

func main() {
    let args = CommandLine.arguments

    guard args.count >= 2 else {
        printUsage()
        exit(1)
    }

    let command = args[1]

    switch command {
    case "get":
        guard args.count >= 4 else {
            fputs("Error: 'get' requires <service> and <account>\n", stderr)
            exit(1)
        }

        let service = args[2]
        let account = args[3]

        guard !isInternalKeychainItem(service: service, account: account) else {
            fputs("Error: Access to internal keychain items is not allowed\n", stderr)
            exit(1)
        }

        // Touch ID authentication
        guard
            authenticateWithTouchID(
                reason: "access the password of \(account)@\(service)",
                cacheKey: "\(account)@\(service)"
            )
        else {
            exit(1)
        }

        if let password = getKeychainPassword(
            service: service,
            account: account
        ) {
            print(password)
        } else {
            exit(1)
        }

    case "set":
        guard args.count >= 4 else {
            fputs("Error: 'set' requires <service> and <account>\n", stderr)
            exit(1)
        }

        let service = args[2]
        let account = args[3]

        guard !isInternalKeychainItem(service: service, account: account) else {
            fputs("Error: Access to internal keychain items is not allowed\n", stderr)
            exit(1)
        }

        // Touch ID authentication first
        guard
            authenticateWithTouchID(
                reason: "set the password of \(account)@\(service)",
                cacheKey: "\(account)@\(service)"
            )
        else {
            exit(1)
        }

        fputs("Enter password: ", stderr)
        guard let password = readSecurePassword(), !password.isEmpty else {
            fputs("Error: No password provided\n", stderr)
            exit(1)
        }

        if setKeychainPassword(
            service: service,
            account: account,
            password: password
        ) {
            fputs("Password saved successfully\n", stderr)
        } else {
            exit(1)
        }

    case "delete":
        guard args.count >= 4 else {
            fputs("Error: 'delete' requires <service> and <account>\n", stderr)
            exit(1)
        }

        let service = args[2]
        let account = args[3]

        guard !isInternalKeychainItem(service: service, account: account) else {
            fputs("Error: Access to internal keychain items is not allowed\n", stderr)
            exit(1)
        }

        // Touch ID authentication
        guard
            authenticateWithTouchID(
                reason: "delete the password of \(account)@\(service).",
                cacheKey: "\(account)@\(service)"
            )
        else {
            exit(1)
        }

        if deleteKeychainPassword(service: service, account: account) {
            fputs("Password deleted successfully\n", stderr)
        } else {
            exit(1)
        }

    case "list":
        // Touch ID authentication
        guard
            authenticateWithTouchID(
                reason: "list items in your keychains",
                cacheKey: "list"
            )
        else {
            exit(1)
        }

        let service = args.count >= 3 ? args[2] : nil
        let items = listKeychainItems(service: service)

        if items.isEmpty {
            print("No items found")
        } else {
            let serviceHeader = "Service"
            let accountHeader = "Account"
            let serviceWidth = max(
                serviceHeader.count,
                items.map(\.service.count).max() ?? 0
            )
            let padService: (String) -> String = { value in
                value
                    + String(
                        repeating: " ",
                        count: max(0, serviceWidth - value.count)
                    )
            }

            print("\(padService(serviceHeader))  \(accountHeader)")
            print(
                "\(String(repeating: "-", count: serviceWidth))  \(String(repeating: "-", count: accountHeader.count))"
            )
            for item in items {
                print("\(padService(item.service))  \(item.account)")
            }
        }

    case "help", "-h", "--help":
        printUsage()

    default:
        fputs("Unknown command: \(command)\n", stderr)
        printUsage()
        exit(1)
    }
}

main()
