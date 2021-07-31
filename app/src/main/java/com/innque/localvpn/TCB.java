package com.innque.localvpn;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Map;

/**
 * Transmission Control Block
 */
public class TCB {
    public String ipAndPort;

    public long lSequenceNum;
    public long rSequence;
    public long lAcknowledgement;
    public long rAcknowledgement;

    public TCBStatus status;

    public enum TCBStatus {SYN_SENT, SYN_RECEIVED, ESTABLISHED}

    public Packet packet;

    public SocketChannel channel;
    public boolean waitingForNetworkData;
    public SelectionKey selectionKey;

    private static final int MAX_CACHE_SIZE = 50;
    private static LRUCache<String, TCB> cache = new LRUCache<>(MAX_CACHE_SIZE, new LRUCache.CleanupCallback<String, TCB>() {
        @Override
        public void cleanup(Map.Entry<String, TCB> eldest) {
            eldest.getValue().closeChannel();
        }
    });

    public static TCB getTCB(String ipAndPort) {
        synchronized (cache) {
            return cache.get(ipAndPort);
        }
    }

    public static void putTCB(String ipAndPort, TCB tcb) {
        synchronized (cache) {
            cache.put(ipAndPort, tcb);
        }
    }

    public TCB(String ipAndPort, long lSequenceNum, long rSequence, long lAcknowledgement, long rAcknowledgement,
               SocketChannel channel, Packet packet) {
        this.ipAndPort = ipAndPort;

        this.lSequenceNum = lSequenceNum;
        this.rSequence = rSequence;
        this.lAcknowledgement = lAcknowledgement;
        this.rAcknowledgement = rAcknowledgement;

        this.channel = channel;
        this.packet = packet;
    }

    public static void closeTCB(TCB tcb) {
        tcb.closeChannel();
        synchronized (cache) {
            cache.remove(tcb.ipAndPort);
        }
    }

    public static void closeAll() {
        synchronized (cache) {
            Iterator<Map.Entry<String, TCB>> it = cache.entrySet().iterator();
            while (it.hasNext()) {
                it.next().getValue().closeChannel();
                it.remove();
            }
        }
    }

    private void closeChannel() {
        try {
            channel.close();
        } catch (IOException e) {
            // Ignore
        }
    }
}
