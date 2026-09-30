package android.app;

import android.content.Intent;

/** Minimal Activity stub with lifecycle entry points. */
public class Activity {
    public void onCreate(Object savedInstanceState) {}

    public void onNewIntent(Intent intent) {}

    public void onActivityResult(int requestCode, int resultCode, Intent data) {}

    public void startActivity(Intent intent) {}

    public Intent getIntent() {
        return new Intent();
    }
}
