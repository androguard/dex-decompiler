package android.content;

/** Minimal Intent stub for precision-2 live DEX demos. */
public class Intent {
    private String action;
    private Object nested;

    public Intent() {}

    public Intent(String action) {
        this.action = action;
    }

    public String getAction() {
        return action;
    }

    public String getStringExtra(String key) {
        return key == null ? null : "extra:" + key;
    }

    public Intent getParcelableExtra(String key) {
        return (Intent) nested;
    }

    public Intent putExtra(String key, String value) {
        return this;
    }

    public Intent putExtra(String key, Intent value) {
        this.nested = value;
        return this;
    }
}
