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

public class ConnectionReceive implements Runnable {
    private static final String TAG = "ConnectionReceive";

    private static final int HEADER_SIZE = IPHeader.SIZE + TCPHeader.SIZE;

    private Selector selector;
    private ConcurrentLinkedQueue<ByteBuffer> localQueue;

    public ConnectionReceive(Selector selector, ConcurrentLinkedQueue<ByteBuffer> localQueue) {
        this.selector = selector;
        this.localQueue = localQueue;
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
                    connected(key);
                }
                if (key.isReadable()) {
                    read(key);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "run: ", e);
        }
    }

    public void connected(SelectionKey key) throws IOException {
        TCB tcb = (TCB) key.attachment();
        Packet packet = tcb.packet;
        if (tcb.channel.finishConnect()) {
            tcb.status = TCB.TCBStatus.SYN_RECEIVED;
            packet.update((byte) (TCPHeader.SYN + TCPHeader.ACK), tcb.lSequenceNum, tcb.lAcknowledgement, 0);
            localQueue.offer(packet.buffer);
            tcb.lSequenceNum++; // next sequence
            // update to read event
            key.interestOps(SelectionKey.OP_READ);
        }
    }

    public void read(SelectionKey key) throws IOException {
        TCB tcb = (TCB) key.attachment();
        Packet packet = tcb.packet;
        ByteBuffer buffer = packet.buffer;
        buffer.position(HEADER_SIZE);
        // read data
        SocketChannel channel = (SocketChannel) key.channel();
        int size = channel.read(buffer);
        packet.update((byte) (TCPHeader.PSH + TCPHeader.ACK), tcb.lSequenceNum, tcb.lAcknowledgement, size);
        tcb.lSequenceNum += size; // Next sequence number
        packet.buffer.position(HEADER_SIZE + size);
        localQueue.offer(packet.buffer);
    }


}
