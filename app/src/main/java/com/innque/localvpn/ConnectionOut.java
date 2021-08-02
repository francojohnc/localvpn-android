package com.innque.localvpn;

import android.net.VpnService;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;

public class ConnectionOut implements Runnable {
    private static final String TAG = "ConnectionOut";
    private Selector selector;
    private ConcurrentLinkedQueue<Packet> deviceToNetworkQueue;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
    private VpnService vpn;
    private Random random = new Random();

    public ConnectionOut(Selector selector, ConcurrentLinkedQueue<Packet> deviceToNetworkQueue, ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue, VpnService vpn) {
        this.selector = selector;
        this.deviceToNetworkQueue = deviceToNetworkQueue;
        this.networkToDeviceQueue = networkToDeviceQueue;
        this.vpn = vpn;
    }


    @Override
    public void run() {
        try {
            while (true) {
                Packet packet = deviceToNetworkQueue.poll();
                if (packet == null) {
                    continue;
                }

                ByteBuffer buffer = packet.buffer;

                InetAddress destinationAddress = packet.ipHeader.getDestinationAddress();
                TCPHeader tcpHeader = packet.tcpHeader;
                Log.d(TAG, "to Remote: " + packet.ipHeader.toString());
                Log.d(TAG, "to Remote: " + packet.tcpHeader.toString());

                int destinationPort = tcpHeader.getDestinationPort();
                int sourcePort = tcpHeader.getSourcePort();

                String ipAndPort = destinationAddress.getHostAddress() + ":" + destinationPort + ":" + sourcePort;
                TCB tcb = TCB.getTCB(ipAndPort);
                if (tcb == null) {
                    initializeConnection(ipAndPort, packet);
                } else if (tcpHeader.isACK()) {
                    processACK(tcb, tcpHeader, buffer, packet);
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    private void initializeConnection(String ipAndPort, Packet packet) throws IOException {
        TCPHeader tcpHeader = packet.tcpHeader;
        InetAddress destinationAddress = packet.ipHeader.getDestinationAddress();
        int destinationPort = tcpHeader.getDestinationPort();
        packet.swapSourceAndDestination();
        if (tcpHeader.isSYN()) {
            SocketChannel channel = SocketChannel.open();
            channel.configureBlocking(false);
            vpn.protect(channel.socket());

            TCB tcb = new TCB(ipAndPort, random.nextInt(Short.MAX_VALUE + 1), tcpHeader.getSequenceNumber(), tcpHeader.getSequenceNumber() + 1,
                    tcpHeader.getAcknowledgmentNumber(), channel, packet);
            TCB.putTCB(ipAndPort, tcb);

            channel.connect(new InetSocketAddress(destinationAddress, destinationPort));
            tcb.status = TCB.TCBStatus.SYN_SENT;
            selector.wakeup();
            tcb.selectionKey = channel.register(selector, SelectionKey.OP_CONNECT, tcb);
        }
    }


    private void processACK(TCB tcb, TCPHeader tcpHeader, ByteBuffer payloadBuffer, Packet packet2) throws IOException {
        byte[] data = packet2.getData();
        int payloadSize = data.length;
        synchronized (tcb) {
            SocketChannel outputChannel = tcb.channel;
            if (tcb.status == TCB.TCBStatus.SYN_RECEIVED) {
                tcb.status = TCB.TCBStatus.ESTABLISHED;
                selector.wakeup();
                tcb.selectionKey = outputChannel.register(selector, SelectionKey.OP_READ, tcb);
                tcb.waitingForNetworkData = true;
            }
            if (payloadSize == 0) return; // Empty ACK, ignore
            if (!tcb.waitingForNetworkData) {
                selector.wakeup();
                tcb.selectionKey.interestOps(SelectionKey.OP_READ);
                tcb.waitingForNetworkData = true;
            }

            // Forward to remote server
            try {
                while (payloadBuffer.hasRemaining())
                    outputChannel.write(payloadBuffer);
            } catch (IOException e) {
            }
            tcb.lAcknowledgement = tcpHeader.getSequenceNumber() + payloadSize;
            tcb.rAcknowledgement = tcpHeader.getAcknowledgmentNumber();
            Packet packet = tcb.packet;
            packet.update((byte) TCPHeader.ACK, tcb.lSequenceNum, tcb.lAcknowledgement, 0);
            networkToDeviceQueue.offer(packet.buffer);
        }
    }
}
