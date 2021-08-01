package com.innque.localvpn;

import android.net.VpnService;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Connection implements Runnable {
    private static final String TAG = "Connection";
    private FileDescriptor fd;
    private VpnService vpn;

    private Selector selector;
    private ConcurrentLinkedQueue<Packet> deviceToNetworkQueue;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
    private ExecutorService executorService;


    public Connection(FileDescriptor fd, VpnService vpn) {
        this.fd = fd;
        this.vpn = vpn;
        try {
            selector = Selector.open();
        } catch (IOException e) {
            e.printStackTrace();
        }
        deviceToNetworkQueue = new ConcurrentLinkedQueue<>();
        networkToDeviceQueue = new ConcurrentLinkedQueue<>();
        executorService = Executors.newFixedThreadPool(2);
        executorService.submit(new ConnectionOut(selector, deviceToNetworkQueue, networkToDeviceQueue, vpn));
        executorService.submit(new ConnectionIn(selector, networkToDeviceQueue));
    }


    @Override
    public void run() {
        Log.e(TAG, "run: ");
        FileChannel in = new FileInputStream(this.fd).getChannel();
        FileChannel out = new FileOutputStream(this.fd).getChannel();

        boolean dataSent = false;
        boolean dataReceived = false;
        ByteBuffer buffer = ByteBuffer.allocate(1500);
        try {

            while (true) {
                if (dataSent) {
                    buffer = ByteBuffer.allocate(1500);
                } else {
                    buffer.clear();
                }
                int size = in.read(buffer);
                Log.v(TAG, "run:size " + size + "\n");
                if (size > 0) {
                    dataSent = true;
                    buffer.flip();
                    Packet packet = new Packet(buffer);
                    if (packet.ipHeader.destinationAddress.getHostName().equals("192.168.254.108")) {
                        deviceToNetworkQueue.offer(packet);
                    } else {
                        dataSent = false;
                    }
                } else {
                    dataSent = false;
                }
                ByteBuffer bufferNetwork = networkToDeviceQueue.poll();
                if (bufferNetwork != null) {
                    bufferNetwork.flip();
//                    Packet2 packet = new Packet2(bufferNetwork);
//                    Log.d(TAG, "to Local: " + packet.tcpHeader.toString());
                    bufferNetwork.position(0);
                    out.write(bufferNetwork);
                    dataReceived = true;
                    bufferNetwork.clear();
                } else {
                    dataReceived = false;
                }
                if (!dataSent && !dataReceived) {
                    Thread.sleep(10);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Exception: ", e);
        }
        Log.e(TAG, "done: ");
    }
}
