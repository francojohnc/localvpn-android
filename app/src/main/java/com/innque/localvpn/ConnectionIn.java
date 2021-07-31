package com.innque.localvpn;

import android.util.Log;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

public class ConnectionIn implements Runnable {
    private static final String TAG = "ConnectionIn";

    private static final int HEADER_SIZE = 40;

    private Selector selector;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;

    public ConnectionIn(Selector selector, ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue) {
        this.selector = selector;
        this.networkToDeviceQueue = networkToDeviceQueue;
    }


    @Override
    public void run() {
        try {
            while (!Thread.interrupted()) {
                if (selector.select() == 0) {
                    Thread.sleep(10);
                    continue;
                }
                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> iterator = keys.iterator();
                SelectionKey key = null;
                while (iterator.hasNext()) {
                    key = iterator.next();
                    iterator.remove();
                }
                if (key.isConnectable()) {
                    processConnect(key);
                }
                if (key.isReadable()) {
                    processInput(key);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "run: ", e);
        }
    }

    private void processConnect(SelectionKey key) {
        TCB tcb = (TCB) key.attachment();
        Packet packet = tcb.packet;
        try {
            if (tcb.channel.finishConnect()) {
                tcb.status = TCB.TCBStatus.SYN_RECEIVED;
                packet.updateTCPBuffer((byte) (Packet.TCPHeader.SYN | Packet.TCPHeader.ACK), tcb.lSequenceNum, tcb.lAcknowledgement, 0);
                networkToDeviceQueue.offer(packet.buffer);
                tcb.lSequenceNum++;
                // update to read event
                key.interestOps(SelectionKey.OP_READ);
            }
        } catch (IOException e) {
        }
    }

    private void processInput(SelectionKey key) throws IOException {
        TCB tcb = (TCB) key.attachment();
        synchronized (tcb) {
            Packet packet = tcb.packet;
            ByteBuffer buffer = packet.buffer;
            buffer.position(HEADER_SIZE);
            SocketChannel channel = (SocketChannel) key.channel();
            int size;
            size = channel.read(buffer);
            packet.updateTCPBuffer((byte) (Packet.TCPHeader.PSH + Packet.TCPHeader.ACK), tcb.lSequenceNum, tcb.lAcknowledgement, size);
            tcb.lSequenceNum += size; // Next sequence number
            packet.buffer.position(HEADER_SIZE + size);
            networkToDeviceQueue.offer(packet.buffer);
        }
    }
}
