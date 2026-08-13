//! Bundled default Android models / rules (Mariana Trench–inspired kinds).

use super::config::TaintConfig;

/// Default configuration embedded in the binary.
pub fn default_config() -> TaintConfig {
    TaintConfig::from_json_str(DEFAULT_JSON).expect("embedded default taint config must parse")
}

const DEFAULT_JSON: &str = r#"{
  "sources": [
    {"patterns": ["getIntent", "Activity.getIntent"], "port": "return", "kind": "ActivityUserInput", "features": ["user-controlled"]},
    {"patterns": ["getStringExtra", "getCharSequenceExtra", "getParcelableExtra", "getSerializableExtra", "getDataString", "Intent.getData"], "port": "return", "kind": "ActivityUserInput"},
    {"patterns": ["getQueryParameter", "Uri.getQueryParameter", "getLastPathSegment"], "port": "return", "kind": "ActivityUserInput"},
    {"patterns": ["EditText.getText"], "port": "return", "kind": "UserInput"},
    {"patterns": ["ClipboardManager.getPrimaryClip", "ClipboardManager.getText"], "port": "return", "kind": "Clipboard"},
    {"patterns": ["getDeviceId", "getImei", "getSubscriberId", "getAndroidId", "Settings$Secure.getString"], "port": "return", "kind": "DeviceId"},
    {"patterns": ["getLastLocation", "getCurrentLocation", "getLatitude", "getLongitude"], "port": "return", "kind": "Location"},
    {"patterns": ["onReceive", "BroadcastReceiver"], "port": {"argument": {"index": 0}}, "kind": "ReceiverUserInput"},
    {"patterns": ["query", "ContentResolver.query"], "port": "return", "kind": "ProviderUserInput"},
    {"patterns": ["getInstalledPackages", "createPackageContext", "getApplicationInfo", "File.getAbsolutePath", "Environment.getExternalStorageDirectory"], "port": "return", "kind": "UntrustedCodePath"}
  ],
  "sinks": [
    {"patterns": ["Runtime.exec", "ProcessBuilder.<init>", "ProcessBuilder.start"], "port": {"argument": {"index": 0}}, "kind": "CodeExecution"},
    {"patterns": ["DexClassLoader.<init>", "PathClassLoader.<init>", "InMemoryDexClassLoader.<init>"], "port": {"argument": {"index": 1}}, "kind": "CodeExecution"},
    {"patterns": ["loadClass", "System.load", "System.loadLibrary"], "port": {"argument": {"index": 1}}, "kind": "CodeExecution"},
    {"patterns": ["rawQuery", "execSQL", "compileStatement"], "port": {"argument": {"index": 1}}, "kind": "SQLQuery"},
    {"patterns": ["WebView.loadUrl", "loadUrl", "loadData", "loadDataWithBaseURL", "evaluateJavascript"], "port": {"argument": {"index": 1}}, "kind": "ExecuteJavascript"},
    {"patterns": ["addJavascriptInterface"], "port": {"argument": {"index": 1}}, "kind": "JavascriptInterface"},
    {"patterns": ["setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"], "port": {"argument": {"index": 1}}, "kind": "WebViewFileAccess"},
    {"patterns": ["Log.d", "Log.i", "Log.w", "Log.e", "Log.v", "println"], "port": {"argument": {"index": 1}}, "kind": "Logging"},
    {"patterns": ["startActivity", "startActivityForResult", "startService", "bindService", "sendBroadcast", "sendOrderedBroadcast"], "port": {"argument": {"index": 1}}, "kind": "LaunchingComponent"},
    {"patterns": ["setResult"], "port": {"argument": {"index": 2}}, "kind": "SetResult"},
    {"patterns": ["openConnection", "HttpURLConnection", "OkHttpClient", "Request.Builder.url"], "port": {"argument": {"index": 0}}, "kind": "Network"},
    {"patterns": ["FileOutputStream.<init>", "FileWriter.<init>", "openFileOutput", "ParcelFileDescriptor.open"], "port": {"argument": {"index": 1}}, "kind": "FileWrite"},
    {"patterns": ["java.io.File.<init>", "File.<init>"], "port": {"argument": {"index": 2}}, "kind": "FileWrite"},
    {"patterns": ["SharedPreferences$Editor.putString", "Editor.putString"], "port": {"argument": {"index": 2}}, "kind": "SharedPrefsWrite"},
    {"patterns": ["ObjectInputStream.readObject", "readObject"], "port": {"argument": {"index": 0}}, "kind": "Deserialization"},
    {"patterns": ["SecretKeySpec.<init>", "IvParameterSpec.<init>"], "port": {"argument": {"index": 1}}, "kind": "WeakCrypto"}
  ],
  "propagations": [
    {"patterns": ["StringBuilder.append", "StringBuffer.append"], "from": {"argument": {"index": 1}}, "to": {"argument": {"index": 0}}},
    {"patterns": ["StringBuilder.toString", "StringBuffer.toString"], "from": {"argument": {"index": 0}}, "to": "return"},
    {"patterns": ["String.valueOf", "String.copyValueOf", "concat"], "from": {"argument": {"index": 0}}, "to": "return"},
    {"patterns": ["Uri.parse", "Uri.Builder.build", "Uri.Builder.appendQueryParameter"], "from": {"argument": {"index": 0}}, "to": "return"},
    {"patterns": ["Intent.putExtra", "putExtra"], "from": {"argument": {"index": 2}}, "to": {"argument": {"index": 0}}},
    {"patterns": ["Intent.setData", "setData", "setDataAndType"], "from": {"argument": {"index": 1}}, "to": {"argument": {"index": 0}}},
    {"patterns": ["Bundle.putString", "putCharSequence"], "from": {"argument": {"index": 2}}, "to": {"argument": {"index": 0}}},
    {"patterns": ["setLoginUrl"], "from": {"argument": {"index": 1}}, "to": {"argument": {"index": 0}}}
  ],
  "sanitizers": [
    {"patterns": ["MessageDigest.digest", "MessageDigest.update", "hashCode", "Objects.hash"], "kinds": ["*"]},
    {"patterns": ["URLEncoder.encode", "Uri.encode"], "kinds": ["ActivityUserInput", "UserInput"]},
    {"patterns": ["Base64.encode", "Base64.encodeToString"], "kinds": []}
  ],
  "rules": [
    {
      "name": "User input to code execution (RCE)",
      "code": 1,
      "description": "User-/intent-controlled values may flow into a code-execution sink",
      "sources": ["ActivityUserInput", "UserInput", "ReceiverUserInput", "ProviderUserInput", "UntrustedCodePath"],
      "sinks": ["CodeExecution"]
    },
    {
      "name": "User input to SQL",
      "code": 4,
      "description": "User-controlled values may flow into a raw SQL statement",
      "sources": ["ActivityUserInput", "UserInput", "ReceiverUserInput", "ProviderUserInput"],
      "sinks": ["SQLQuery"]
    },
    {
      "name": "User input to WebView / JS",
      "code": 5,
      "description": "User-controlled values may flow into WebView script execution",
      "sources": ["ActivityUserInput", "UserInput", "ReceiverUserInput"],
      "sinks": ["ExecuteJavascript", "JavascriptInterface", "WebViewFileAccess"]
    },
    {
      "name": "User input to intent launch",
      "code": 3,
      "description": "User-controlled values may flow into an intent launcher",
      "sources": ["ActivityUserInput", "UserInput", "ReceiverUserInput"],
      "sinks": ["LaunchingComponent", "SetResult"]
    },
    {
      "name": "PII to logging",
      "code": 10,
      "description": "Device identifiers or location may flow into logs",
      "sources": ["DeviceId", "Location", "Clipboard", "ActivityUserInput", "UserInput"],
      "sinks": ["Logging", "Network"]
    },
    {
      "name": "User input to network",
      "code": 11,
      "description": "User-controlled values may flow into network APIs",
      "sources": ["ActivityUserInput", "UserInput"],
      "sinks": ["Network"]
    },
    {
      "name": "User input to file write",
      "code": 12,
      "description": "User-controlled values may flow into file write APIs",
      "sources": ["ActivityUserInput", "UserInput", "ProviderUserInput"],
      "sinks": ["FileWrite"]
    },
    {
      "name": "User input to shared preferences",
      "code": 13,
      "description": "User-controlled values may be written into SharedPreferences",
      "sources": ["ActivityUserInput", "UserInput"],
      "sinks": ["SharedPrefsWrite"]
    },
    {
      "name": "User input to deserialization",
      "code": 14,
      "description": "User-controlled values may reach unsafe deserialization",
      "sources": ["ActivityUserInput", "UserInput", "ReceiverUserInput"],
      "sinks": ["Deserialization"]
    }
  ]
}"#;
