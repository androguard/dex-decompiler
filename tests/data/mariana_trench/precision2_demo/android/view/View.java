package android.view;

/** Minimal View + OnClickListener stubs for callback shim demos. */
public class View {
    public interface OnClickListener {
        void onClick(View v);
    }

    public void setOnClickListener(OnClickListener listener) {
        // framework dispatch → listener.onClick (shimmed by solver)
    }
}
