import Foundation

enum AppConfig {
    /// Where the attestation proxy runs. Set `WoosmapProxyBaseURL` in Info.plist.
    static let proxyBaseURL: URL = {
        let value = Bundle.main.object(forInfoDictionaryKey: "WoosmapProxyBaseURL") as? String
        return URL(string: value ?? "http://localhost:8000")!
    }()

    /// Identifies this app to the proxy. Not a secret; it must match CLIENT_ID in the proxy.
    static let clientId = "woozies-ios"

    /// App Attest doesn't run in the simulator, so debug builds there use a debug token instead.
    /// It must be listed in ATTEST_DEBUG_TOKENS on the proxy. Release builds never send one.
    #if DEBUG
    static let debugAttestationToken: String? = "woozies-simulator-debug"
    #else
    static let debugAttestationToken: String? = nil
    #endif

    static var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
    }
}
