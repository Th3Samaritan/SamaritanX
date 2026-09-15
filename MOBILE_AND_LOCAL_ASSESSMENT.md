# Local privilege and mobile assessments

## Implemented scope

Windows/Linux local privilege assessment is read-only. It accepts a JSON inventory
or explicitly collects configuration on the local host. Checks include root-owned
world-writable files, setuid inventory, broad sudo rules, unquoted privileged
Windows service paths and the two AlwaysInstallElevated policy scopes. It does not
execute a local privilege-escalation exploit or prove a path exploitable.

Android static assessment reads plain or compiled APK manifests. It reviews debug
and test flags, cleartext policy, backup policy and exported components. iOS static
assessment reads binary or XML Info.plist files from IPA archives and reviews ATS
exceptions, document sharing and URL schemes. Files are inspected inside bounded
ZIP readers without extracting or executing app contents. Unresolved Android
resource policies are marked unavailable; coverage is partial in that case.

Dynamic assessment supports Android UiAutomator2 and iOS XCUITest through existing
Appium sessions. It verifies the foreground package/bundle identifier before UI
inspection and every action, inventories webviews, and identifies password-named
fields that may lack secure input controls. Optional click/type flows require
`--aggressive`; text comes from environment variables. The adapter stops on app
identity mismatch, allows at most 250 Appium operations and has a 180-second overall
deadline. It never automatically installs an app, roots or jailbreaks a device,
or injects runtime code. The workflow must stay within the chosen application.

Scoped HAR review covers recorded traffic from either platform, flags HTTP requests,
and exports GET/HEAD API seeds with no captured headers, cookies, body values or
query values. Sensitive query parameters are excluded from seeds. The existing
scanner imports those seeds through TaskQueue and checks target scope before
scheduling; passive mode does not schedule API seeds. Configure separate test-user
auth recipes for authorization and privilege comparisons.

## Commands

```powershell
python samaritanx.py local-audit --collect --output workspace/local-audit
python samaritanx.py local-audit --snapshot inventory.json --output workspace/local-audit
python samaritanx.py mobile-static app.apk --output workspace/android-static
python samaritanx.py mobile-static app.ipa --output workspace/ios-static
python samaritanx.py mobile-dynamic --platform android --app-id com.example.app --session-id SESSION --appium-url http://127.0.0.1:4723 --output workspace/android-dynamic
python samaritanx.py mobile-dynamic --platform ios --app-id com.example.app --session-id SESSION --appium-url https://your-appium-host --output workspace/ios-dynamic
python samaritanx.py mobile-traffic capture.har --scope-host api.example.test --output workspace/mobile-traffic
python samaritanx.py scan https://api.example.test --scope config/scope.example.txt --api-seeds workspace/mobile-traffic/api-seeds.json
```

For UI flows, supply `--flow config/mobile-flow.example.json --aggressive` and set
`SX_TEST_PASSWORD` in the environment. Adapt selectors to the authorized app.
No typed values or raw UI text are retained in assessment reports. HAR paths and
parameter names remain in API seeds; review their sensitivity before sharing.

Each assessment writes `assessment.json`, `assessment.md` and `candidates.json`.
These are separate from verified web findings. No static flag or UI observation
is promoted to a verified vulnerability automatically. A blocked Appium assessment
writes its unavailable-capability reason and exits with code 2.

## Runtime setup and actual-device validation

The Python client talks directly to Appium over HTTP; a Python Appium SDK is not
required. Start an Appium server with the appropriate UiAutomator2 or XCUITest
driver, establish a session for your app, open the app, then provide its session
ID and exact package/bundle identifier. iOS XCUITest requires a macOS device host;
SamaritanX can connect from Windows to that host. Real iOS device signing and Android
device authorization must be configured on the Appium host. This implementation
attaches to sessions rather than creating or deleting them.

Official driver references:
- https://github.com/appium/appium-uiautomator2-driver
- https://appium.github.io/appium-xcuitest-driver/latest/reference/execute-methods/

This workspace currently has no adb, Appium or Xcode runtime. Validation uses paired
APK/IPA fixtures and both in-memory and actual loopback Appium protocol fixtures.
No claim of real-device, emulator or production-application validation is made.

## Coverage limits

This is an initial assessment capability, not full MASVS coverage. It does not yet
resolve Android resource tables, analyze DEX/native data flows, verify IPA signing
or entitlements, inspect app sandbox/keychain contents, bypass pinning, or prove
backend authorization solely from UI output. HAR HTTPS entries do not prove
certificate validation or pinning. Use the existing scoped backend scanner for
API testing and independently verify candidates on authorized test accounts.

## Validation results

345 unit tests and 158 structural checks passed. APK/IPA, local snapshot and HAR CLI smoke tests passed. Real loopback Appium protocol fixtures passed for both platforms. Existing resource and three-adapter smoke gates passed. Compilation and diff checks passed. No real mobile device validation was performed.
