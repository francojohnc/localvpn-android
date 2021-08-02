package com.innque.localvpn;

import android.net.VpnService;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * responsible for sending data to remote
 */
public class ConnectionSend implements Runnable {
    private VpnService vpn;
    private Selector selector;
    private Random random = new Random();
    private ConcurrentLinkedQueue<ByteBuffer> localQueue;
    private ConcurrentLinkedQueue<Packet> remoteQueue;

    public ConnectionSend(Selector selector, ConcurrentLinkedQueue<Packet> remoteQueue, ConcurrentLinkedQueue<ByteBuffer> localQueue, VpnService vpn) {
        this.vpn = vpn;
        this.localQueue = localQueue;
        this.remoteQueue = remoteQueue;
        this.selector = selector;
    }

    @Override
    public void run() {
        while (!Thread.interrupted()) {
            Packet packet = remoteQueue.poll();
            if (packet == null) {
                continue;
            }
            try {
                this.send(packet);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void send(Packet packet) throws IOException {
        IPHeader ipHeader = packet.ipHeader;
        TCPHeader tcpHeader = packet.tcpHeader;

        InetAddress destinationAddress = ipHeader.getDestinationAddress();
        int destinationPort = tcpHeader.getDestinationPort();
        int sourcePort = tcpHeader.getSourcePort();

        String id = destinationAddress.getHostAddress() + ":" + destinationPort + ":" + sourcePort;
        TCB tcb = TCB.getTCB(id);
        if (tcb == null) {
            initializeConnection(id, packet);
        } else if (tcpHeader.isACK()) {
            processACK(tcb, packet);
        }

    }


    // first connection
    public void initializeConnection(String id, Packet packet) throws IOException {
        IPHeader ipHeader = packet.ipHeader;
        TCPHeader tcpHeader = packet.tcpHeader;
        //
        InetAddress destinationAddress = ipHeader.getDestinationAddress();
        int destinationPort = tcpHeader.getDestinationPort();

        if (tcpHeader.isSYN()) {
            // create socket connection
            SocketChannel channel = SocketChannel.open();
            channel.configureBlocking(false);
            vpn.protect(channel.socket());
            channel.connect(new InetSocketAddress(destinationAddress, destinationPort));


            // reuse packet
            packet.swapSourceAndDestination();
            long lSequence = random.nextInt(Short.MAX_VALUE + 1);
            long rSequence = tcpHeader.getSequenceNumber();
            long lAcknowledge = tcpHeader.getSequenceNumber() + 1;
            long rAcknowledge = tcpHeader.getAcknowledgmentNumber();

            TCB tcb = new TCB(id, lSequence, rSequence, lAcknowledge, rAcknowledge, channel, packet);
            TCB.putTCB(id, tcb);

            // register to selector
            tcb.status = TCB.TCBStatus.SYN_SENT;
            selector.wakeup();
            tcb.selectionKey = channel.register(selector, SelectionKey.OP_CONNECT, tcb);
        }
    }

    public void processACK(TCB tcb, Packet packet) throws IOException {
        IPHeader ipHeader = packet.ipHeader;
        TCPHeader tcpHeader = packet.tcpHeader;

        byte[] data = packet.getData();
        int size = data.length;
        synchronized (tcb) {
            SocketChannel channel = tcb.channel;
            // update tcp status
            if (tcb.status == TCB.TCBStatus.SYN_RECEIVED) {
                tcb.status = TCB.TCBStatus.ESTABLISHED;
                selector.wakeup();
                tcb.selectionKey = channel.register(selector, SelectionKey.OP_READ, tcb);
                tcb.waitingForNetworkData = true;
            }
            if (size == 0) return; // Empty ACK, ignore
            // forward data to remote server
            channel.write(ByteBuffer.wrap(data));
            // send ACK to local
            tcb.lAcknowledgement = tcpHeader.getSequenceNumber() + size;
            tcb.rAcknowledgement = tcpHeader.getAcknowledgmentNumber();
            tcb.packet.update((byte) TCPHeader.ACK, tcb.lSequenceNum, tcb.lAcknowledgement, 0);
            localQueue.offer(tcb.packet.buffer);
        }
    }


}
