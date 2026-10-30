package com.woosmap.app.woozies

import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** An error returned by the proxy, with its machine-readable code (for example "app_token_expired"). */
class ProxyError(val status: Int, val code: String?) : Exception() {
    override val message: String
        get() = when (code) {
            "app_token_missing", "app_token_invalid", "app_token_expired", "app_token_revoked" ->
                "The app couldn't prove it's genuine ($code). Try again."
            "play_integrity_not_configured" ->
                "The proxy has Play Integrity turned off. Set PLAY_INTEGRITY_CREDENTIALS."
            "debug_token_invalid" ->
                "The proxy didn't accept the emulator debug token. Add it to ATTEST_DEBUG_TOKENS."
            "upstream_auth_failed" ->
                "Woosmap rejected the app's key. Check WOOSMAP_API_KEY in secrets.properties and its Android restriction."
            "woosmap_key_missing" ->
                "The app has no Woosmap key. Set WOOSMAP_API_KEY in secrets.properties and rebuild."
            "upstream_unavailable" -> "The proxy couldn't reach Woosmap. Check its network connection."
            else -> if (code?.startsWith("play_integrity_") == true) {
                "Play Integrity didn't verify this app ($code)."
            } else {
                "The proxy returned HTTP $status${code?.let { " ($it)" } ?: ""}."
            }
        }

    val isAppTokenProblem: Boolean get() = status == 401 && code?.startsWith("app_token") == true

    companion object {
        fun from(status: Int, body: String?): ProxyError {
            val code = runCatching { JSONObject(body ?: "").optString("error").ifEmpty { null } }.getOrNull()
            return ProxyError(status, code)
        }
    }
}

data class AppToken(val value: String, val refreshAfterMillis: Long)

/** Calls the proxy's attestation endpoints. */
class ProxyApi(private val baseUrl: String = AppConfig.proxyBaseUrl) {

    suspend fun challenge(): String = post("attest/challenge", JSONObject()).getString("challenge")

    suspend fun debugToken(token: String): AppToken =
        tokenRequest("attest/debug/token", JSONObject().put("debug_token", token))

    suspend fun androidToken(integrityToken: String, challenge: String): AppToken =
        tokenRequest(
            "attest/android/token",
            JSONObject().put("integrity_token", integrityToken).put("challenge", challenge),
        )

    private suspend fun tokenRequest(path: String, body: JSONObject): AppToken {
        val response = post(path, body)
        // Refresh at 80% of the lifetime so calls never go out with an expiring token.
        val refreshAfter = System.currentTimeMillis() + response.getLong("expires_in") * 800
        return AppToken(response.getString("token"), refreshAfter)
    }

    private suspend fun post(path: String, body: JSONObject): JSONObject = withContext(Dispatchers.IO) {
        val connection = URL("$baseUrl/$path").openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("X-Client-Id", AppConfig.CLIENT_ID)
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            JSONObject(connection.readBody())
        } finally {
            connection.disconnect()
        }
    }
}

/** The response body, or a [ProxyError] for any non-2xx status. */
internal fun HttpURLConnection.readBody(): String {
    val status = responseCode
    if (status !in 200..299) {
        throw ProxyError.from(status, errorStream?.bufferedReader()?.use { it.readText() })
    }
    return inputStream.bufferedReader().use { it.readText() }
}
