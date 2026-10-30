import Foundation

/// Calls Localities Nearby through the proxy, attaching the app token.
struct LocalitiesClient {
    var baseURL = AppConfig.proxyBaseURL
    var attestation = AttestationService.shared
    var session = URLSession.shared

    func nearby(latitude: Double, longitude: Double, types: String,
                radius: Int, page: Int = 1) async throws -> NearbyResponse {
        let query = [
            URLQueryItem(name: "types", value: types),
            URLQueryItem(name: "location", value: "\(latitude),\(longitude)"),
            URLQueryItem(name: "radius", value: String(radius)),
            URLQueryItem(name: "page", value: String(page)),
        ]
        do {
            return try await send(query, token: try await attestation.currentToken())
        } catch let error as ProxyError where error.isAppTokenProblem {
            // Token expired or was revoked: get a fresh one and retry once.
            return try await send(query, token: try await attestation.currentToken(forceRefresh: true))
        }
    }

    private func send(_ query: [URLQueryItem], token: String) async throws -> NearbyResponse {
        var components = URLComponents(url: baseURL.appendingPathComponent("localities/nearby"),
                                       resolvingAgainstBaseURL: false)!
        components.queryItems = query
        var request = URLRequest(url: components.url!)
        request.setValue(token, forHTTPHeaderField: "X-Woosmap-App-Token")
        request.setValue(AppConfig.clientId, forHTTPHeaderField: "X-Client-Id")
        request.setValue(Bundle.main.bundleIdentifier, forHTTPHeaderField: "X-iOS-Identifier")
        request.setValue(AppConfig.appVersion, forHTTPHeaderField: "X-App-Version")

        let (data, response) = try await session.data(for: request)
        try ProxyError.check(data, response)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(NearbyResponse.self, from: data)
    }
}
