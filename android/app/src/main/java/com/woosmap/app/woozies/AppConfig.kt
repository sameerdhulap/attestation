package com.woosmap.app.woozies

/** Build-time settings, from secrets.properties via BuildConfig. */
object AppConfig {
    /** Where the attestation proxy runs. */
    val proxyBaseUrl: String = BuildConfig.PROXY_BASE_URL.trimEnd('/')

    /** Woosmap key, forwarded by the proxy as X-Api-Key. */
    val woosmapApiKey: String? = BuildConfig.WOOSMAP_API_KEY.ifEmpty { null }

    /** Identifies this app to the proxy. Not a secret; it must match CLIENT_ID in the proxy. */
    const val CLIENT_ID = "woozies-ios"

    /** Google Cloud project number for Play Integrity; 0 when not set up. */
    val playIntegrityProjectNumber: Long = BuildConfig.PLAY_INTEGRITY_PROJECT_NUMBER

    /** Emulators can't pass Play Integrity, so debug builds there use this token instead. */
    val debugAttestationToken: String? = BuildConfig.DEBUG_ATTESTATION_TOKEN.ifEmpty { null }

    const val APP_VERSION = BuildConfig.VERSION_NAME
}
