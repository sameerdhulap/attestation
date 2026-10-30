import Foundation

enum AppConfig {
    /// Where the attestation proxy runs. Set `WoosmapProxyBaseURL` in Info.plist.
    static let proxyBaseURL: URL = {
        let value = Bundle.main.object(forInfoDictionaryKey: "WoosmapProxyBaseURL") as? String
        return URL(string: value ?? "http://localhost:8000")!
    }()

    /// Woosmap key, forwarded by the proxy as X-Api-Key. Set `WOOSMAP_API_KEY` in Config/Secrets.xcconfig.
    static let woosmapAPIKey: String? = {
        let value = Bundle.main.object(forInfoDictionaryKey: "WoosmapAPIKey") as? String
        return value?.isEmpty == false ? value : nil
    }()

    /// Apple Team ID, sent as X-Apple-Team-Id when registering an App Attest key. Comes from DEVELOPMENT_TEAM.
    static let appleTeamID: String? = {
        let value = Bundle.main.object(forInfoDictionaryKey: "AppleTeamID") as? String
        return value?.isEmpty == false ? value : nil
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
