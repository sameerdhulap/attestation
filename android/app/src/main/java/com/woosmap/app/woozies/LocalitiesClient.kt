package com.woosmap.app.woozies

import android.content.Context
import android.content.pm.PackageManager
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Calls Localities Nearby through the proxy, attaching the app token and Android identifiers. */
class LocalitiesClient(context: Context, private val attestation: AttestationService) {
    private val packageName = context.packageName
    private val fingerprint = signingSha1(context)

    suspend fun nearby(latitude: Double, longitude: Double, types: String, radius: Int): List<Locality> {
        val query = mapOf(
            "types" to types,
            "location" to "$latitude,$longitude",
            "radius" to radius.toString(),
            "page" to "1",
        )
        return try {
            send(query, attestation.currentToken())
        } catch (e: ProxyError) {
            if (!e.isAppTokenProblem) throw e
            // Token expired or was revoked: get a fresh one and retry once.
            send(query, attestation.currentToken(forceRefresh = true))
        }
    }

    private suspend fun send(query: Map<String, String>, token: String): List<Locality> =
        withContext(Dispatchers.IO) {
            val encoded = query.entries.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, "UTF-8")}" }
            val connection = URL("${AppConfig.proxyBaseUrl}/localities/nearby?$encoded")
                .openConnection() as HttpURLConnection
            try {
                connection.setRequestProperty("X-Woosmap-App-Token", token)
                connection.setRequestProperty("X-Client-Id", AppConfig.CLIENT_ID)
                AppConfig.woosmapApiKey?.let { connection.setRequestProperty("X-Api-Key", it) }
                connection.setRequestProperty("X-Android-Identifier", packageName)
                fingerprint?.let { connection.setRequestProperty("X-Android-Fingerprint", it) }
                connection.setRequestProperty("X-App-Version", AppConfig.APP_VERSION)
                Locality.parseNearby(connection.readBody())
            } finally {
                connection.disconnect()
            }
        }

    private companion object {
        /** SHA-1 of the signing certificate, as keytool prints it (AA:BB:...). Woosmap checks it against the key's restriction. */
        fun signingSha1(context: Context): String? {
            val info = context.packageManager.getPackageInfo(
                context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val cert = info.signingInfo?.apkContentsSigners?.firstOrNull() ?: return null
            return MessageDigest.getInstance("SHA-1").digest(cert.toByteArray())
                .joinToString(":") { "%02X".format(it) }
        }
    }
}
