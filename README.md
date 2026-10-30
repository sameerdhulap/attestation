# Woozies: App Attest + proxy example for the Woosmap Localities API

This example shows how an iOS app can call the Localities Nearby API through a proxy that only answers the genuine app.

The app proves it's the genuine, unmodified Woozies app using Apple App Attest. A small Python proxy verifies that proof, then forwards the call, with the Woosmap key (`X-Api-Key`) and bundle ID (`X-iOS-Identifier`) the app sent, to `https://api.woosmap.com/localities/nearby`. The proxy holds no Woosmap key. Calling the proxy with copied headers gets an attacker nothing, because it only answers apps holding a valid app token, and only App Attest can produce one.

```
iOS app (com.woosmap.app.woozies)            Python proxy                         Woosmap
  1. POST /attest/challenge  ─────────────▶  issues a one-time challenge
  2. App Attest proof        ─────────────▶  verifies with Apple's root CA
     + X-Apple-Team-Id                        against TEAMID.bundle ID
                              ◀─────────────  short-lived app token
  3. GET /localities/nearby  ─────────────▶  checks token, keeps allowed params,
     + X-Woosmap-App-Token                    forwards X-Api-Key and
     + X-Api-Key, X-iOS-Identifier            X-iOS-Identifier              ──▶  /localities/nearby
                              ◀─────────────  passes the result back         ◀──
```

## What's in the box

| Folder | Contents |
| --- | --- |
| `proxy/` | FastAPI proxy: App Attest verification, an optional Firebase App Check path, a simulator debug-token path, and the Localities forwarding |
| `proxy/attestation/` | The attestation core from the base implementation (App Attest, tokens, gateway check) |
| `proxy/tests/` | 20 tests, including a fake Apple authority so App Attest runs without a device |
| `ios/` | SwiftUI app plus an XcodeGen `project.yml` |

## 1. Run the proxy

```bash
cd proxy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                      # optional: 20 tests
uvicorn woozies_proxy.main:build_app --factory --host 0.0.0.0 --port 8000 --reload
```

`proxy/.env` already holds the simulator debug token, so the proxy starts straight away. It needs no Woosmap key. `.env` is git-ignored; `.env.example` documents every setting.

Check the setup at `http://localhost:8000/health`. It reports whether App Attest, Firebase and debug tokens are enabled.

**To turn on App Attest for real devices:**

1. Download Apple's App Attestation Root CA from [Apple's Certificate Authority page](https://www.apple.com/certificateauthority/) and save it as `proxy/certs/Apple_App_Attestation_Root_CA.pem`.
2. Restart the proxy. `/health` should now show `"app_attest": true`.

The proxy doesn't need your Team ID. The app sends it as `X-Apple-Team-Id` when it registers its App Attest key, and the proxy checks the attestation against `<Team ID>.<IOS_BUNDLE_ID>`.

## 2. Run the iOS app

```bash
brew install xcodegen
cd ios
cp Config/Secrets.xcconfig.example Config/Secrets.xcconfig   # then set WOOSMAP_API_KEY
xcodegen
open Woozies.xcodeproj
```

`Config/Secrets.xcconfig` is git-ignored. The key must allow the bundle ID `com.woosmap.app.woozies`, because the app sends it as `X-iOS-Identifier`.

Set `DEVELOPMENT_TEAM` in `project.yml` to your Team ID before running `xcodegen`; the app reads it from Info.plist (`AppleTeamID`). In Xcode, open the Woozies target's *Signing & Capabilities*, check your team is selected, and check that the *App Attest* capability is listed. XcodeGen adds it from `project.yml` with the `development` environment.

If you'd rather not use XcodeGen, create a new SwiftUI iOS app named Woozies with the bundle ID `com.woosmap.app.woozies`, drag in the files from `ios/Woozies`, add the App Attest capability, and add `WoosmapProxyBaseURL`, `WoosmapAPIKey` and `NSAppTransportSecurity → NSAllowsLocalNetworking = YES` to Info.plist.

**Simulator:** App Attest doesn't run in the simulator, so debug builds there send the debug token instead. It works out of the box against `http://localhost:8000`.

**Real device:** set `WoosmapProxyBaseURL` in `project.yml` (or Info.plist) to your Mac's local IP, such as `http://192.168.1.20:8000`. Run `xcodegen` again, then build to the device. The first search registers an App Attest key; later searches refresh the token with an assertion.

## 3. Try it

Tap **Find nearby places**. The default coordinates are central Paris. The *App verification* section shows how the app was verified, and the proxy log shows every forwarded call with the captured app headers and query.

To see the protection working, try calling the proxy the way an attacker would:

```bash
curl -i "http://localhost:8000/localities/nearby?types=point_of_interest&location=48.863469,2.330941" \
  -H "X-Client-Id: woozies-ios" \
  -H "X-Api-Key: copied-from-the-app" \
  -H "X-iOS-Identifier: com.woosmap.app.woozies"
```

You'll get `401 {"error":"app_token_missing"}`. Woosmap is never called.

## How the proxy handles a call

For `GET /localities/nearby`, the proxy does the following:

1. It checks `X-Woosmap-App-Token`: the signature, expiry, which client it's bound to, and the deny list. In `enforce` mode, anything invalid gets a 401 with a code such as `app_token_expired`. The app refreshes once on these codes and retries.
2. It captures the app headers `X-Client-Id`, `X-iOS-Identifier`, `X-App-Version` and `User-Agent`, plus the token's claims, in the log.
3. It forwards only the documented query parameters: `types`, `location`, `radius`, `page`, `limit` and `excluded_types`. Anything else, including a `key` or `private_key` a caller tries to slip in, is dropped and logged.
4. It calls Woosmap with the app's `X-Api-Key` and `X-iOS-Identifier`, passing on `Accept-Language` if present. If either header is missing, it returns `400 woosmap_key_missing` or `400 ios_identifier_missing` instead.
5. It returns Woosmap's status and JSON unchanged, with one exception. A 401 or 403 from Woosmap means the app's key is wrong or restricted, so it becomes `502 upstream_auth_failed`. That way the app never confuses it with its own token being rejected.

`ATTEST_MODE` controls step 1: `enforce` rejects, `monitor` forwards but logs unverified calls, and `off` skips the check.

## Firebase App Check (optional)

The Woozies app doesn't use Firebase, but the proxy supports it for apps that do. Set `FIREBASE_PROJECT_NUMBER` and `FIREBASE_APP_IDS` in `.env`. An app then sends its App Check token to `POST /attest/firebase/token` (with `X-Client-Id`) and gets the same kind of app token back. Until those settings exist, the endpoint returns `503 firebase_not_configured`.

## Before going beyond a demo

- **Treat the app's key as public:** it ships inside the app, so anyone can pull it out of the binary and call Woosmap directly with the bundle ID header, bypassing the proxy. Restrict it in the Woosmap Console to the iOS bundle ID and the products you use, and watch its usage.
- **Mind the Team ID header:** the proxy accepts any Team ID the app sends, so attestation only proves the app is signed with *some* team for `IOS_BUNDLE_ID`. That holds as long as the bundle ID is registered to your team in your Apple Developer account, because Apple won't issue it to anyone else.
- **Turn off debug tokens:** leave `ATTEST_DEBUG_TOKENS` empty anywhere other than a developer machine.
- **Use production builds:** App Store and TestFlight builds attest in the `production` environment. Set the entitlement to `production` and `IOS_ALLOW_DEVELOPMENT=false`.
- **Keep the signing key stable:** set `ATTEST_SIGNING_KEY` (create one with `openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem`). Otherwise every restart invalidates issued tokens.
- **Use shared state:** registered App Attest keys live in memory, so a proxy restart means devices re-register. That's handled automatically, but production needs a database, and Redis for challenges.
- **Serve over HTTPS:** put the proxy behind TLS and rate-limit the `/attest/*` endpoints.
