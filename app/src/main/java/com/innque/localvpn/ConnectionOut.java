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

                InetAddress destinationAddress = packet.ipHeader.destinationAddress;
                Packet.TCPHeader tcpHeader = packet.tcpHeader;
                Log.d(TAG, "to Remote: " + packet.ipHeader.toString());
                Log.d(TAG, "to Remote: " + tcpHeader.toString());

                int destinationPort = tcpHeader.destinationPort;
                int sourcePort = tcpHeader.sourcePort;

                String ipAndPort = destinationAddress.getHostAddress() + ":" + destinationPort + ":" + sourcePort;
                TCB tcb = TCB.getTCB(ipAndPort);
                if (tcb == null) {
                    initializeConnection(ipAndPort, destinationAddress, destinationPort, packet, tcpHeader);
                } else if (tcpHeader.isACK()) {
                    processACK(tcb, tcpHeader, buffer);
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    private void initializeConnection(String ipAndPort, InetAddress destinationAddress, int destinationPort,
                                      Packet packet, Packet.TCPHeader tcpHeader)
            throws IOException {
        packet.swapSourceAndDestination();
        if (tcpHeader.isSYN()) {
            SocketChannel channel = SocketChannel.open();
            channel.configureBlocking(false);
            vpn.protect(channel.socket());

            TCB tcb = new TCB(ipAndPort, random.nextInt(Short.MAX_VALUE + 1), tcpHeader.sequenceNumber, tcpHeader.sequenceNumber + 1,
                    tcpHeader.acknowledgementNumber, channel, packet);
            TCB.putTCB(ipAndPort, tcb);

            channel.connect(new InetSocketAddress(destinationAddress, destinationPort));
            tcb.status = TCB.TCBStatus.SYN_SENT;
            selector.wakeup();
            tcb.selectionKey = channel.register(selector, SelectionKey.OP_CONNECT, tcb);
        }
    }


    private void processACK(TCB tcb, Packet.TCPHeader tcpHeader, ByteBuffer payloadBuffer) throws IOException {
        int payloadSize = payloadBuffer.limit() - payloadBuffer.position();
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
            tcb.lAcknowledgement = tcpHeader.sequenceNumber + payloadSize;
            tcb.rAcknowledgement = tcpHeader.acknowledgementNumber;
            Packet packet = tcb.packet;
            packet.updateTCPBuffer((byte) TCPHeader.ACK, tcb.lSequenceNum, tcb.lAcknowledgement, 0);
            networkToDeviceQueue.offer(packet.buffer);
        }
    }
}
