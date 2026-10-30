import Foundation

@MainActor
final class NearbyViewModel: ObservableObject {
    struct PlaceType: Hashable {
        let label: String
        let value: String
    }

    static let placeTypes = [
        PlaceType(label: "Points of interest", value: "point_of_interest"),
        PlaceType(label: "Businesses", value: "business"),
        PlaceType(label: "Food and drinks", value: "business.food_and_drinks"),
    ]

    @Published var latitude = "48.863469"
    @Published var longitude = "2.330941"
    @Published var radius = 1000.0
    @Published var placeType = NearbyViewModel.placeTypes[0]
    @Published private(set) var results: [Locality] = []
    @Published private(set) var isLoading = false
    @Published private(set) var hasSearched = false
    @Published private(set) var errorMessage: String?
    @Published private(set) var attestationStatus = "Not checked yet"

    private let client = LocalitiesClient()

    var canSearch: Bool { Double(latitude) != nil && Double(longitude) != nil && !isLoading }

    func search() async {
        guard let lat = Double(latitude), let lng = Double(longitude) else {
            errorMessage = "Enter a latitude and longitude as decimal numbers, for example 48.8634."
            return
        }
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }
        do {
            let response = try await client.nearby(latitude: lat, longitude: lng,
                                                   types: placeType.value, radius: Int(radius))
            results = response.results
        } catch {
            results = []
            errorMessage = error.localizedDescription
        }
        hasSearched = true
        await refreshStatus()
    }

    func resetAttestation() async {
        await AttestationService.shared.reset()
        await refreshStatus()
    }

    private func refreshStatus() async {
        switch await AttestationService.shared.state {
        case .notStarted: attestationStatus = "Not checked yet"
        case .attested(let method): attestationStatus = "Verified with \(method)"
        case .failed(let reason): attestationStatus = "Not verified: \(reason)"
        }
    }
}
