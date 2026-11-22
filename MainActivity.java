package com.pureadguard.mobile;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST = 41;
    private TextView status;
    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 48, 32, 32);
        layout.setGravity(Gravity.CENTER);
        layout.setBackgroundColor(0xFF101010);
        TextView title = new TextView(this);
        title.setText("PURE AD GUARD");
        title.setTextColor(0xFFFFFFFF);
        title.setTextSize(26);
        title.setGravity(Gravity.CENTER);
        status = new TextView(this);
        status.setText("Protection is OFF");
        status.setTextColor(0xFFCCCCCC);
        status.setTextSize(16);
        status.setGravity(Gravity.CENTER);
        Button on = new Button(this);
        on.setText("TURN ON");
        on.setOnClickListener(v -> {
            Intent prep = VpnService.prepare(this);
            if (prep != null) startActivityForResult(prep, VPN_REQUEST);
            else startProtection();
        });
        Button off = new Button(this);
        off.setText("TURN OFF");
        off.setOnClickListener(v -> {
            stopService(new Intent(this, AdBlockVpnService.class));
            status.setText("Protection is OFF");
        });
        TextView note = new TextView(this);
        note.setText("DNS filtering blocks supported ad domains. YouTube in-stream ads may still appear.");
        note.setTextColor(0xFFAAAAAA);
        note.setGravity(Gravity.CENTER);
        note.setPadding(8, 28, 8, 8);
        layout.addView(title); layout.addView(status); layout.addView(on); layout.addView(off); layout.addView(note);
        setContentView(layout);
    }
    private void startProtection() {
        Intent i = new Intent(this, AdBlockVpnService.class);
        startForegroundService(i);
        status.setText("Protection requested");
    }
    @Override protected void onActivityResult(int r, int c, Intent d) {
        super.onActivityResult(r,c,d);
        if (r == VPN_REQUEST && c == RESULT_OK) startProtection();
    }
}
