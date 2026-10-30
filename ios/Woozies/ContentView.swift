import SwiftUI

struct ContentView: View {
    @StateObject private var model = NearbyViewModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("Search around") {
                    LabeledContent("Latitude") {
                        TextField("48.8634", text: $model.latitude)
                            .keyboardType(.numbersAndPunctuation)
                            .multilineTextAlignment(.trailing)
                    }
                    LabeledContent("Longitude") {
                        TextField("2.3309", text: $model.longitude)
                            .keyboardType(.numbersAndPunctuation)
                            .multilineTextAlignment(.trailing)
                    }
                    Picker("Type", selection: $model.placeType) {
                        ForEach(NearbyViewModel.placeTypes, id: \.self) { Text($0.label).tag($0) }
                    }
                    VStack(alignment: .leading) {
                        Text("Radius: \(Int(model.radius)) m")
                        Slider(value: $model.radius, in: 100...5000, step: 100)
                    }
                    Button {
                        Task { await model.search() }
                    } label: {
                        HStack {
                            Text("Find nearby places")
                            if model.isLoading { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(!model.canSearch)
                }

                if let error = model.errorMessage {
                    Section { Text(error).foregroundStyle(.red) }
                }

                Section("Results") {
                    if model.results.isEmpty {
                        Text(model.hasSearched
                             ? "No places found. Try a larger radius or another type."
                             : "Search to see places near these coordinates.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.results) { place in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(place.displayName)
                            if !place.subtitle.isEmpty {
                                Text(place.subtitle).font(.footnote).foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Section {
                    Text(model.attestationStatus)
                    Button("Reset App Attest key", role: .destructive) {
                        Task { await model.resetAttestation() }
                    }
                } header: {
                    Text("App verification")
                } footer: {
                    Text("Requests go through the attestation proxy at \(AppConfig.proxyBaseURL.absoluteString). Woosmap only answers once the proxy has verified the app.")
                }
            }
            .navigationTitle("Woozies")
        }
    }
}

#Preview {
    ContentView()
}
