package com.woosmap.app.woozies

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyErrorTest {
    @Test
    fun readsErrorCode() {
        val error = ProxyError.from(401, """{"error":"app_token_expired"}""")
        assertEquals("app_token_expired", error.code)
        assertTrue(error.isAppTokenProblem)
    }

    @Test
    fun playIntegrityFailureIsNotRetried() {
        val error = ProxyError.from(401, """{"error":"play_integrity_device_failed"}""")
        assertFalse(error.isAppTokenProblem)
        assertEquals("Play Integrity didn't verify this app (play_integrity_device_failed).", error.message)
    }

    @Test
    fun handlesNonJsonBody() {
        val error = ProxyError.from(502, "Bad Gateway")
        assertEquals(null, error.code)
        assertEquals("The proxy returned HTTP 502.", error.message)
    }
}
