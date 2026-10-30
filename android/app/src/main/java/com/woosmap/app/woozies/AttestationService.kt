package com.woosmap.app.woozies

import android.content.Context
import android.os.Build
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Gets and caches the proxy's app token.
 *
 * On a real device it asks Google Play Integrity for a verdict bound to a one-time
 * challenge from the proxy, which checks it with Google. On an emulator, where Play
 * Integrity can't pass, debug builds use a debug token instead.
 */
class AttestationService(context: Context, private val api: ProxyApi = ProxyApi()) {
    private val appContext = context.applicationContext
    private val mutex = Mutex()
    private var token: AppToken? = null

    var status: String = "Not checked yet"
        private set

    /** A valid app token, fetching a new one when needed. */
    suspend fun currentToken(forceRefresh: Boolean = false): String = mutex.withLock {
        token?.takeIf { !forceRefresh && it.refreshAfterMillis > System.currentTimeMillis() }
            ?.let { return it.value }
        try {
            fetchToken().also { token = it }.value
        } catch (e: Exception) {
            status = "Not verified: ${e.message}"
            throw e
        }
    }

    fun reset() {
        token = null
        status = "Not checked yet"
    }

    private suspend fun fetchToken(): AppToken {
        val debugToken = AppConfig.debugAttestationToken
        if (debugToken != null && isEmulator()) {
            return api.debugToken(debugToken).also { status = "Verified with Debug token (emulator)" }
        }
        check(AppConfig.playIntegrityProjectNumber != 0L) {
            "Play Integrity isn't set up. Set PLAY_INTEGRITY_PROJECT_NUMBER in secrets.properties."
        }
        val challenge = api.challenge()
        val integrityToken = requestIntegrityToken(challenge)
        return api.androidToken(integrityToken, challenge).also { status = "Verified with Play Integrity" }
    }

    /** The proxy's challenge is base64url, so it's used as the Play Integrity nonce as-is. */
    private suspend fun requestIntegrityToken(nonce: String): String =
        suspendCancellableCoroutine { cont ->
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .setCloudProjectNumber(AppConfig.playIntegrityProjectNumber)
                .build()
            IntegrityManagerFactory.create(appContext).requestIntegrityToken(request)
                .addOnSuccessListener { cont.resume(it.token()) }
                .addOnFailureListener { cont.resumeWithException(it) }
        }

    private fun isEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") || Build.HARDWARE in setOf("ranchu", "goldfish") ||
            Build.PRODUCT.contains("sdk")
}
