package com.woosmap.app.woozies

import org.json.JSONArray
import org.json.JSONObject

/** The parts of a Localities Nearby result this app shows. */
data class Locality(
    val publicId: String?,
    val name: String?,
    val types: List<String>,
    val categories: List<String>,
    val formattedAddress: String?,
) {
    val displayName: String get() = name ?: formattedAddress ?: "Unnamed place"
    val subtitle: String get() = categories.ifEmpty { types }.joinToString(", ")

    companion object {
        fun parseNearby(body: String): List<Locality> {
            val results = JSONObject(body).optJSONArray("results") ?: return emptyList()
            return (0 until results.length()).map { i ->
                val item = results.getJSONObject(i)
                Locality(
                    publicId = item.optStringOrNull("public_id"),
                    name = item.optStringOrNull("name"),
                    types = item.optJSONArray("types").strings(),
                    categories = item.optJSONArray("categories").strings(),
                    formattedAddress = item.optStringOrNull("formatted_address"),
                )
            }
        }
    }
}

private fun JSONObject.optStringOrNull(name: String): String? =
    if (has(name) && !isNull(name)) getString(name) else null

private fun JSONArray?.strings(): List<String> =
    if (this == null) emptyList() else (0 until length()).map { getString(it) }
