package com.pureadguard.mobile;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

public class AdBlockVpnService extends VpnService {
    private ParcelFileDescriptor tun;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private static final String[] BLOCKED = {
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adservice.google.com", "adnxs.com", "adsystem.com", " تبلیغات"
    };
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        createNotification();
        try {
            tun = new Builder().setSession("PURE AD GUARD")
                .addAddress("10.10.10.1", 32)
                .addDnsServer("10.10.10.2")
                .addRoute("10.10.10.2", 32)
                .setMtu(1500).establish();
            if (tun == null) { stopSelf(); return START_NOT_STICKY; }
            running.set(true);
            new Thread(this::runLoop, "PureAdGuard-DNS").start();
        } catch (Exception e) { stopSelf(); }
        return START_STICKY;
    }
    private void createNotification() {
        String id = "pure_ad_guard";
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(id, "PURE AD GUARD", NotificationManager.IMPORTANCE_LOW);
            getSystemService(NotificationManager.class).createNotificationChannel(ch);
        }
        Notification.Builder nb = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, id) : new Notification.Builder(this);
        startForeground(7, nb.setContentTitle("PURE AD GUARD").setContentText("DNS protection is active").setSmallIcon(android.R.drawable.ic_secure).build());
    }
    private void runLoop() {
        byte[] buf = new byte[32767];
        try (FileInputStream in = new FileInputStream(tun.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(tun.getFileDescriptor())) {
            while (running.get()) {
                int n = in.read(buf);
                if (n <= 0) continue;
                byte[] packet = Arrays.copyOf(buf, n);
                byte[] response = handle(packet);
                if (response != null) out.write(response);
            }
        } catch (Exception ignored) { }
    }
    private byte[] handle(byte[] p) {
        try {
            if (p.length < 28 || (p[0] >> 4) != 4 || (p[9] & 255) != 17) return null;
            int ihl = (p[0] & 15) * 4;
            int dstPort = ((p[ihl+2]&255)<<8) | (p[ihl+3]&255);
            if (dstPort != 53) return null;
            int len = ((p[ihl+4]&255)<<8) | (p[ihl+5]&255);
            byte[] dns = Arrays.copyOfRange(p, ihl+8, Math.min(p.length, ihl+len));
            String domain = readDomain(dns);
            byte[] answer;
            if (isBlocked(domain)) answer = nxdomain(dns);
            else answer = forwardDns(dns);
            if (answer == null) return null;
            return makeIpv4UdpResponse(p, ihl, answer);
        } catch (Exception e) { return null; }
    }
    private String readDomain(byte[] d) {
        if (d.length < 17) return "";
        StringBuilder s = new StringBuilder(); int i = 12;
        while (i < d.length) {
            int l = d[i++] & 255; if (l == 0) break;
            if ((l & 0xC0) != 0 || i+l > d.length) return "";
            if (s.length() > 0) s.append('.');
            s.append(new String(d, i, l)); i += l;
        }
        return s.toString().toLowerCase();
    }
    private boolean isBlocked(String d) {
        for (String x : BLOCKED) if (!x.trim().isEmpty() && (d.equals(x) || d.endsWith("." + x))) return true;
        return false;
    }
    private byte[] nxdomain(byte[] q) {
        byte[] a = Arrays.copyOf(q, q.length);
        a[2] = (byte)0x81; a[3] = (byte)0x83;
        a[6]=0; a[7]=0; a[8]=0; a[9]=0; a[10]=0; a[11]=0;
        return a;
    }
    private byte[] forwardDns(byte[] q) {
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(2500); s.connect(InetAddress.getByName("1.1.1.1"), 53);
            if (!protect(s)) return null;
            s.send(new DatagramPacket(q, q.length));
            byte[] b = new byte[4096]; DatagramPacket r = new DatagramPacket(b,b.length); s.receive(r);
            return Arrays.copyOf(r.getData(), r.getLength());
        } catch (Exception e) { return nxdomain(q); }
    }
    private byte[] makeIpv4UdpResponse(byte[] req, int ihl, byte[] dns) {
        int udpLen = 8 + dns.length, total = ihl + udpLen;
        byte[] r = new byte[total];
        System.arraycopy(req,0,r,0,ihl);
        for(int i=0;i<4;i++){ r[12+i]=req[16+i]; r[16+i]=req[12+i]; }
        r[2]=(byte)(total>>8); r[3]=(byte)total; r[8]=64; r[10]=0; r[11]=0;
        int src=((req[ihl]&255)<<8)|(req[ihl+1]&255), dst=((req[ihl+2]&255)<<8)|(req[ihl+3]&255);
        r[ihl]=(byte)(dst>>8); r[ihl+1]=(byte)dst; r[ihl+2]=(byte)(src>>8); r[ihl+3]=(byte)src;
        r[ihl+4]=(byte)(udpLen>>8); r[ihl+5]=(byte)udpLen; r[ihl+6]=0; r[ihl+7]=0;
        System.arraycopy(dns,0,r,ihl+8,dns.length);
        int sum=0;
        for(int i=0;i<ihl;i+=2) sum += ((r[i]&255)<<8)|(r[i+1]&255);
        while((sum>>16)!=0) sum=(sum&65535)+(sum>>16);
        int c=(~sum)&65535; r[10]=(byte)(c>>8); r[11]=(byte)c;
        return r;
    }
    @Override public void onDestroy() {
        running.set(false);
        try { if (tun != null) tun.close(); } catch(Exception ignored) {}
        super.onDestroy();
    }
}
