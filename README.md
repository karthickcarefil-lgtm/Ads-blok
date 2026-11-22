# PURE AD GUARD — Android project

Targeted for Android 13 devices, including Vivo V21e 5G (arm64). Minimum Android 6.0.

## Build APK with GitHub Actions
1. Upload all files/folders in this project to a new GitHub repository.
2. Open the repository's **Actions** tab.
3. Run **Build PURE AD GUARD APK** (or push to main/master).
4. Open the successful workflow run, download artifact `PURE-AD-GUARD-Android13-APK`, unzip it, then install `app-debug.apk`.

## Important limitations
This is an experimental local DNS-filtering VPN. It can block only domains in its DNS block list. YouTube video ads may still appear because YouTube can deliver ads and video from shared infrastructure. It is not a ReVanced patcher and does not modify the YouTube app.
