package android.telephony;

/** Minimal SmsManager stub (sink: sendTextMessage). */
public class SmsManager {
    public static SmsManager getDefault() {
        return new SmsManager();
    }

    public void sendTextMessage(
            String destinationAddress,
            String scAddress,
            String text,
            Object sentIntent,
            Object deliveryIntent) {
        // modelled sink on text (arg index 3 including this → Dalvik: this=0, dest=1, sc=2, text=3)
    }
}
