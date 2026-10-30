package com.woosmap.app.woozies

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch

data class PlaceType(val label: String, val value: String)

class NearbyViewModel(application: Application) : AndroidViewModel(application) {
    private val attestation = AttestationService(application)
    private val client = LocalitiesClient(application, attestation)

    var latitude by mutableStateOf("48.863469")
    var longitude by mutableStateOf("2.330941")
    var radius by mutableStateOf(1000f)
    var placeType by mutableStateOf(PLACE_TYPES.first())
    var results by mutableStateOf<List<Locality>>(emptyList())
        private set
    var isLoading by mutableStateOf(false)
        private set
    var hasSearched by mutableStateOf(false)
        private set
    var errorMessage by mutableStateOf<String?>(null)
        private set
    var attestationStatus by mutableStateOf(attestation.status)
        private set

    val canSearch: Boolean
        get() = latitude.toDoubleOrNull() != null && longitude.toDoubleOrNull() != null && !isLoading

    fun search() {
        val lat = latitude.toDoubleOrNull()
        val lng = longitude.toDoubleOrNull()
        if (lat == null || lng == null) {
            errorMessage = "Enter a latitude and longitude as decimal numbers, for example 48.8634."
            return
        }
        viewModelScope.launch {
            isLoading = true
            errorMessage = null
            try {
                results = client.nearby(lat, lng, placeType.value, radius.toInt())
            } catch (e: Exception) {
                results = emptyList()
                errorMessage = e.message ?: e.toString()
            } finally {
                isLoading = false
                hasSearched = true
                attestationStatus = attestation.status
            }
        }
    }

    fun resetAttestation() {
        attestation.reset()
        attestationStatus = attestation.status
    }

    companion object {
        val PLACE_TYPES = listOf(
            PlaceType("Points of interest", "point_of_interest"),
            PlaceType("Businesses", "business"),
            PlaceType("Food and drinks", "business.food_and_drinks"),
        )
    }
}
