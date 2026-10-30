import Foundation

/// The parts of the Localities Nearby response this app shows.
/// Decoded with `.convertFromSnakeCase`, so `public_id` becomes `publicId`.
struct NearbyResponse: Decodable {
    let results: [Locality]
}

struct Locality: Decodable, Identifiable {
    let publicId: String?
    let name: String?
    let types: [String]?
    let categories: [String]?
    let formattedAddress: String?
    let geometry: Geometry?

    var id: String {
        publicId ?? "\(name ?? "")|\(geometry?.location.lat ?? 0)|\(geometry?.location.lng ?? 0)"
    }

    var displayName: String { name ?? formattedAddress ?? "Unnamed place" }

    var subtitle: String {
        (categories ?? types ?? []).joined(separator: ", ")
    }
}

struct Geometry: Decodable {
    let location: LatLng
}

struct LatLng: Decodable {
    let lat: Double
    let lng: Double
}
