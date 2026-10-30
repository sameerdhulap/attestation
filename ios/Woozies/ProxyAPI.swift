import Foundation

/// An error returned by the proxy, with its machine-readable code (for example "app_token_expired").
struct ProxyError: LocalizedError {
    let status: Int
    let code: String?

    var errorDescription: String? {
        switch code {
        case "app_token_missing", "app_token_invalid", "app_token_expired", "app_token_revoked":
            return "The app couldn't prove it's genuine (\(code!)). Try again."
        case "app_attest_not_configured":
            return "The proxy has App Attest turned off. Add Apple's root certificate to its certs folder."
        case "apple_team_id_missing", "apple_team_id_invalid":
            return "The app has no valid Team ID. Set DEVELOPMENT_TEAM in project.yml and rebuild."
        case "debug_token_invalid":
            return "The proxy didn't accept the simulator debug token. Add it to ATTEST_DEBUG_TOKENS."
        case "upstream_auth_failed":
            return "Woosmap rejected the app's key. Check WOOSMAP_API_KEY in Secrets.xcconfig and its iOS restrictions."
        case "woosmap_key_missing":
            return "The app has no Woosmap key. Set WOOSMAP_API_KEY in Config/Secrets.xcconfig and rebuild."
        case "upstream_unavailable":
            return "The proxy couldn't reach Woosmap. Check its network connection."
        default:
            return "The proxy returned HTTP \(status)\(code.map { " (\($0))" } ?? "")."
        }
    }

    var isAppTokenProblem: Bool { status == 401 && (code?.hasPrefix("app_token") ?? false) }

    static func check(_ data: Data, _ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        guard (200..<300).contains(http.statusCode) else {
            struct Body: Decodable { let error: String? }
            let code = (try? JSONDecoder().decode(Body.self, from: data))?.error
            throw ProxyError(status: http.statusCode, code: code)
        }
    }
}

struct AppToken {
    let value: String
    let refreshAfter: Date
}

/// Calls the proxy's attestation endpoints.
struct ProxyAPI {
    var baseURL = AppConfig.proxyBaseURL
    var clientId = AppConfig.clientId
    var session = URLSession.shared

    func challenge() async throws -> String {
        struct Response: Decodable { let challenge: String }
        let response: Response = try await post("attest/challenge", body: [:])
        return response.challenge
    }

    func registerKey(keyId: String, attestation: Data, challenge: String) async throws -> AppToken {
        try await tokenRequest("attest/ios/register", body: [
            "key_id": keyId, "attestation": attestation.base64EncodedString(), "challenge": challenge,
        ], headers: ["X-Apple-Team-Id": AppConfig.appleTeamID])
    }

    func refreshToken(keyId: String, assertion: Data, challenge: String) async throws -> AppToken {
        try await tokenRequest("attest/ios/token", body: [
            "key_id": keyId, "assertion": assertion.base64EncodedString(), "challenge": challenge,
        ])
    }

    func debugToken(_ token: String) async throws -> AppToken {
        try await tokenRequest("attest/debug/token", body: ["debug_token": token])
    }

    private func tokenRequest(_ path: String, body: [String: String],
                              headers: [String: String?] = [:]) async throws -> AppToken {
        struct Response: Decodable { let token: String; let expires_in: Int }
        let response: Response = try await post(path, body: body, headers: headers)
        // Refresh at 80% of the lifetime so calls never go out with an expiring token.
        let refreshAfter = Date().addingTimeInterval(Double(response.expires_in) * 0.8)
        return AppToken(value: response.token, refreshAfter: refreshAfter)
    }

    private func post<T: Decodable>(_ path: String, body: [String: String],
                                    headers: [String: String?] = [:]) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(clientId, forHTTPHeaderField: "X-Client-Id")
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        try ProxyError.check(data, response)
        return try JSONDecoder().decode(T.self, from: data)
    }
}
