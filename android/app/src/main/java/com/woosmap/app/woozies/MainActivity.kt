package com.woosmap.app.woozies

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { MaterialTheme { NearbyScreen() } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NearbyScreen(model: NearbyViewModel = viewModel()) {
    Scaffold(topBar = { TopAppBar(title = { Text("Woozies") }) }) { padding ->
        LazyColumn(
            modifier = Modifier.padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { SearchForm(model) }
            model.errorMessage?.let { error ->
                item { Text(error, color = MaterialTheme.colorScheme.error) }
            }
            item { SectionTitle("Results") }
            if (model.results.isEmpty()) {
                item {
                    Text(
                        if (model.hasSearched) "No places found. Try a larger radius or another type."
                        else "Search to see places near these coordinates.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            items(model.results, key = { it.publicId ?: it.displayName }) { place ->
                Column {
                    Text(place.displayName)
                    if (place.subtitle.isNotEmpty()) {
                        Text(place.subtitle, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    HorizontalDivider(Modifier.padding(top = 8.dp))
                }
            }
            item { SectionTitle("App verification") }
            item {
                Text(model.attestationStatus)
                TextButton(onClick = model::resetAttestation) {
                    Text("Reset app token", color = MaterialTheme.colorScheme.error)
                }
                Text(
                    "Requests go through the attestation proxy at ${AppConfig.proxyBaseUrl}. " +
                        "Woosmap only answers once the proxy has verified the app.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 24.dp),
                )
            }
        }
    }
}

@Composable
private fun SearchForm(model: NearbyViewModel) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SectionTitle("Search around")
        val decimal = KeyboardOptions(keyboardType = KeyboardType.Decimal)
        OutlinedTextField(model.latitude, { model.latitude = it }, label = { Text("Latitude") },
            singleLine = true, keyboardOptions = decimal, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(model.longitude, { model.longitude = it }, label = { Text("Longitude") },
            singleLine = true, keyboardOptions = decimal, modifier = Modifier.fillMaxWidth())
        TypePicker(model)
        Text("Radius: ${model.radius.toInt()} m")
        Slider(model.radius, { model.radius = it }, valueRange = 100f..5000f, steps = 48)
        Button(onClick = model::search, enabled = model.canSearch, modifier = Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Find nearby places")
                if (model.isLoading) {
                    Spacer(Modifier.width(8.dp))
                    CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                }
            }
        }
    }
}

@Composable
private fun TypePicker(model: NearbyViewModel) {
    var expanded by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Type", Modifier.weight(1f))
        TextButton(onClick = { expanded = true }) { Text(model.placeType.label) }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            NearbyViewModel.PLACE_TYPES.forEach { type ->
                DropdownMenuItem(text = { Text(type.label) }, onClick = {
                    model.placeType = type
                    expanded = false
                })
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp))
}
