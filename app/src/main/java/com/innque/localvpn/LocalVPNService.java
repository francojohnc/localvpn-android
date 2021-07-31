package com.innque.localvpn;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import androidx.core.content.ContextCompat;

public class LocalVPNService extends VpnService {
    public static final String ACTION_CONNECT = "START";
    public static final String ACTION_DISCONNECT = "STOP";
    // VPN Config
    private static final String VPN_ADDRESS = "10.0.0.2"; // Only IPv4 support for now
    private static final String VPN_ROUTE = "0.0.0.0"; // default gateway
    private static final int MTU = 1500; // maximum transport unit
    // local variable
    private ParcelFileDescriptor vpnProfile = null;
    private Thread thread;

    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getAction() != null) {
            switch (intent.getAction()) {
                case ACTION_CONNECT:
                    build();
                    connect();
                    break;
                case ACTION_DISCONNECT:
                    disconnect();
                    break;
            }
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        disconnect();
    }

    private void connect() {
        Connection con = new Connection(vpnProfile.getFileDescriptor(), this);
        thread = new Thread(con);
        thread.start();
    }

    private void disconnect() {
        //stop running thread
        stopForeground(true);
    }

    private void build() {
        //build a vpn interface
        Builder builder = new VpnService.Builder();
        //Add a network address to the VPN interface.
        builder.addAddress(VPN_ADDRESS, 32);
        //Add a network route to the VPN interface.
        builder.addRoute(VPN_ROUTE, 0);
        //Set the maximum transmission unit (MTU) of the VPN interface.
        builder.setMtu(MTU);
        builder.setSession(getString(R.string.app_name));
        // Build configure intent
        Intent configure = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);
        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        //build
        vpnProfile = builder.establish();
    }

    public static void start(Context context) {
        Intent intent = new Intent(context, LocalVPNService.class);
        intent.setAction(ACTION_CONNECT);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void stop(Context context) {
        Intent intent = new Intent(context, LocalVPNService.class);
        intent.setAction(ACTION_DISCONNECT);
        ContextCompat.startForegroundService(context, intent);
    }
}
