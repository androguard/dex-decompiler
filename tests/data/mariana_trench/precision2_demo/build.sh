#!/usr/bin/env bash
# Rebuild the checked-in precision-2 live solver demo DEX.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
if [ -z "${JAVA_HOME:-}" ] && [ -x "/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/javac" ]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
export PATH="${JAVA_HOME:+$JAVA_HOME/bin:}$PATH"
BUILD_TOOLS=""
while IFS= read -r dir; do
  [ -x "$dir/d8" ] && BUILD_TOOLS="$dir"
done < <(ls -1d "$SDK"/build-tools/* 2>/dev/null | sort -V)

if [ -z "$BUILD_TOOLS" ] || [ ! -x "$BUILD_TOOLS/d8" ]; then
  echo "error: Android SDK d8 not found" >&2
  exit 1
fi

WORK="$ROOT/build"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/dex"

SOURCES=(
  "$ROOT/android/content/Intent.java"
  "$ROOT/android/content/Context.java"
  "$ROOT/android/content/BroadcastReceiver.java"
  "$ROOT/android/app/Activity.java"
  "$ROOT/android/view/View.java"
  "$ROOT/android/telephony/SmsMessage.java"
  "$ROOT/android/telephony/SmsManager.java"
  "$ROOT/mt/p2/Precision2Demo.java"
)

javac --release 8 -g -d "$WORK/classes" "${SOURCES[@]}"

CLASS_FILES=()
while IFS= read -r f; do
  CLASS_FILES+=("$f")
done < <(find "$WORK/classes" -name '*.class' | sort)

"$BUILD_TOOLS/d8" --min-api 26 --no-desugaring --output "$WORK/dex" "${CLASS_FILES[@]}"
cp "$WORK/dex/classes.dex" "$ROOT/classes.dex"
echo "wrote $ROOT/classes.dex ($(wc -c < "$ROOT/classes.dex") bytes)"
