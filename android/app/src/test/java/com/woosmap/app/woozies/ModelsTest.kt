package com.woosmap.app.woozies

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelsTest {
    @Test
    fun parsesNearbyResults() {
        val places = Locality.parseNearby(
            """{"results":[{"public_id":"abc","name":"BMC Garden","types":["park"]},
               {"formatted_address":"1 Main St","types":["point_of_interest"],"categories":["hotel"]}]}"""
        )
        assertEquals(listOf("BMC Garden", "1 Main St"), places.map { it.displayName })
        assertEquals("park", places[0].subtitle)
        assertEquals("hotel", places[1].subtitle)
    }

    @Test
    fun emptyWhenNoResults() {
        assertTrue(Locality.parseNearby("{}").isEmpty())
    }
}
