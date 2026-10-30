import CryptoKit
import DeviceCheck
import Foundation

enum AttestationState: Equatable {
    case notStarted
    case attested(method: String)
    case failed(String)
}

/// Gets and caches the proxy's app token.
///
/// On a real device it uses App Attest: the first time, it creates a Secure Enclave key and
/// registers it (attestation); after that, each refresh signs a fresh challenge (assertion).
/// In the simulator, where App Attest isn't available, debug builds use a debug token.
actor AttestationService {
    static let shared = AttestationService()

    private let api = ProxyAPI()
    private let keyStore = KeychainStore(service: "com.woosmap.app.woozies.appattest", account: "keyId")
    private var token: AppToken?
    private var inFlight: Task<AppToken, Error>?
    private(set) var state: AttestationState = .notStarted

    /// A valid app token, fetching or refreshing one when needed.
    func currentToken(forceRefresh: Bool = false) async throws -> String {
        if !forceRefresh, let token, token.refreshAfter > Date() {
            return token.value
        }
        // Share one fetch between concurrent callers.
        if let inFlight {
            return try await inFlight.value.value
        }
        let task = Task { try await self.fetchToken() }
        inFlight = task
        defer { inFlight = nil }
        do {
            let fresh = try await task.value
            token = fresh
            return fresh.value
        } catch {
            state = .failed(error.localizedDescription)
            throw error
        }
    }

    /// Forget the App Attest key, so the next call registers a new one.
    func reset() {
        keyStore.delete()
        token = nil
        state = .notStarted
    }

    private func fetchToken() async throws -> AppToken {
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            if let debugToken = AppConfig.debugAttestationToken {
                let fresh = try await api.debugToken(debugToken)
                state = .attested(method: "Debug token (simulator)")
                return fresh
            }
            throw AttestationFailure.unsupported
        }

        if let keyId = keyStore.read() {
            do {
                let fresh = try await refresh(keyId: keyId, service: service)
                state = .attested(method: "App Attest")
                return fresh
            } catch let error as ProxyError where error.code == "app_attest_unknown_key" {
                keyStore.delete()   // the proxy no longer knows this key: register a new one
            } catch let error as DCError where error.code == .invalidKey {
                keyStore.delete()   // the key was invalidated on the device: register a new one
            }
        }
        let fresh = try await register(service: service)
        state = .attested(method: "App Attest")
        return fresh
    }

    private func register(service: DCAppAttestService) async throws -> AppToken {
        let keyId = try await service.generateKey()
        let challenge = try await api.challenge()
        let attestation = try await service.attestKey(keyId, clientDataHash: Self.hash(challenge))
        let fresh = try await api.registerKey(keyId: keyId, attestation: attestation, challenge: challenge)
        keyStore.save(keyId)
        return fresh
    }

    private func refresh(keyId: String, service: DCAppAttestService) async throws -> AppToken {
        let challenge = try await api.challenge()
        let assertion = try await service.generateAssertion(keyId, clientDataHash: Self.hash(challenge))
        return try await api.refreshToken(keyId: keyId, assertion: assertion, challenge: challenge)
    }

    /// The proxy verifies against SHA-256 of the UTF-8 challenge string.
    private static func hash(_ challenge: String) -> Data {
        Data(SHA256.hash(data: Data(challenge.utf8)))
    }
}

enum AttestationFailure: LocalizedError {
    case unsupported

    var errorDescription: String? {
        "App Attest isn't available on this device, so the app can't prove it's genuine."
    }
}
