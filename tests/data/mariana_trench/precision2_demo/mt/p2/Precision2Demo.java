package mt.p2;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.telephony.SmsManager;
import android.telephony.SmsMessage;
import android.view.View;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;

/**
 * Live DEX demos for precision-2 taint features: lifecycle seeds, click shims,
 * alias/heap paths, map keys, static heap, multi-hop traces, and SMS PII rules.
 */
public final class Precision2Demo {
    private Precision2Demo() {}

    // --- multi-hop traces (D1/D2) -------------------------------------------------

    public static void directFlow() {
        Origin.sink(Origin.source());
    }

    /** One-hop helper (same pattern as live_solver helperFlow). */
    private static Object identity(Object value) {
        return value;
    }

    public static void oneHopFlow() {
        Origin.sink(identity(Origin.source()));
    }

    /** Two-hop call chain: twoHopFlow → mid → leafSink(source). */
    private static void leafSink(Object value) {
        Origin.sink(value);
    }

    private static void mid(Object value) {
        leafSink(value);
    }

    public static void twoHopFlow() {
        mid(Origin.source());
    }

    // --- alias + instance field heap (B1/B2) --------------------------------------

    public static final class Box {
        public Object payload;
    }

    public static void aliasFieldFlow() {
        Box a = new Box();
        Box b = a;
        a.payload = Origin.source();
        Origin.sink(b.payload);
    }

    /** Strong update: second write clears the first kind (negative for Source→Sink). */
    public static void strongUpdateClean() {
        Box a = new Box();
        a.payload = Origin.source();
        a.payload = new Object(); // untainted store must clear path
        Origin.sink(a.payload);
    }

    // --- map:<const-key> paths (B3) -----------------------------------------------

    public static void mapTokenFlow() {
        Map<String, Object> map = new HashMap<>();
        map.put("token", Origin.source());
        Origin.sink(map.get("token"));
    }

    public static void mapOtherKeyClean() {
        Map<String, Object> map = new HashMap<>();
        map.put("token", Origin.source());
        Origin.sink(map.get("other")); // different key — should stay clean
    }

    // --- static field heap M1 → M2 (B4) -------------------------------------------

    public static final class StaticHolder {
        public static Object slot;

        public static void writeSource() {
            slot = Origin.source();
        }

        public static void readToSink() {
            Origin.sink(slot);
        }
    }

    public static void staticHeapFlow() {
        StaticHolder.writeSource();
        StaticHolder.readToSink();
    }

    // --- lifecycle seeds (C1) -----------------------------------------------------

    public static class DeeplinkActivity extends Activity {
        @Override
        public void onNewIntent(Intent intent) {
            // Lifecycle seeds ActivityUserInput on the Intent argument.
            Origin.sink(intent);
            startActivity(intent);
        }
    }

    public static class RedirectReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            Origin.sink(intent);
            context.startActivity(intent);
        }
    }

    // --- click / executor shims (C2/C3) -------------------------------------------

    public static final class TaintedClick implements View.OnClickListener {
        @Override
        public void onClick(View v) {
            Origin.sink(Origin.source());
        }
    }

    public static void clickShimFlow(View view) {
        view.setOnClickListener(new TaintedClick());
    }

    public static final class TaintedRun implements Runnable {
        @Override
        public void run() {
            Origin.sink(Origin.source());
        }
    }

    public static void executorShimFlow(Executor executor) {
        executor.execute(new TaintedRun());
    }

    // --- SMS PII rule family (A1/A2) ----------------------------------------------

    public static void smsPiiFlow(SmsMessage msg) {
        String body = msg.getMessageBody();
        SmsManager.getDefault().sendTextMessage("+15551212", null, body, null, null);
    }
}

/** Synthetic source / sink used by several demos (modelled in models.json). */
final class Origin {
    private Origin() {}

    static Object source() {
        return new Object();
    }

    static void sink(Object value) {
        // modelled sink
    }
}
