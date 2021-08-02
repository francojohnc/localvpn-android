package com.innque.localvpn;

import android.util.Log;

import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Representation Packet
 */

public class Packet {
    private static final String TAG = "ConnectionIn";

    public IPHeader ipHeader;
    public TCPHeader tcpHeader;
    public ByteBuffer buffer;


    public Packet(ByteBuffer buffer) {
        this.buffer = buffer;
        this.ipHeader = new IPHeader(buffer);
        this.tcpHeader = new TCPHeader(buffer, this.ipHeader);
    }


    public void swapSourceAndDestination() {
        this.ipHeader.swapAddress();
        this.tcpHeader.swapPort();
    }

    public void update(byte flags, long sequence, long acknowledge, int payloadSize) {
        this.tcpHeader.setFlags(flags);
        this.tcpHeader.setSequenceNumber(sequence);
        this.tcpHeader.setAcknowledgmentNumber(acknowledge);
        // Reset header size, since we don't need options
        this.tcpHeader.setOffset(TCPHeader.SIZE);
        this.tcpHeader.setChecksum(this.tcpHeader.checksum(payloadSize));
        int totalLength = IPHeader.SIZE + TCPHeader.SIZE + payloadSize;
        ipHeader.setTotalLength(totalLength);
        ipHeader.setChecksum(ipHeader.checksum());
    }

    public byte[] getData() {
        int length = this.ipHeader.getLength(); // IP Header length
        int totalLength = this.ipHeader.getTotalLength(); // Total length of packet
        int offset = this.tcpHeader.getOffset(); // TCP Header length
        int position = length + offset;
        int size = totalLength - position;
        this.buffer.position(position);
        byte[] bytes = new byte[size];
        this.buffer.get(bytes);
        return bytes;
    }

}
