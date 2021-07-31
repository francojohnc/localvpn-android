package com.innque.localvpn;


import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Representation of an IP Packet
 */
public class Packet2 {
    public IPHeader ipHeader;
    public TCPHeader tcpHeader;
    public ByteBuffer buffer;

    public Packet2(ByteBuffer buffer) {
        this.buffer = buffer;
        this.ipHeader = new IPHeader(this.buffer);
        this.tcpHeader = new TCPHeader(this.buffer, this.ipHeader);
    }

    public void swapSourceAndDestination() throws UnknownHostException {
        this.ipHeader.swapAddress();
        this.tcpHeader.swapPort();
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

    public void setData(byte[] bytes) {
        int length = this.ipHeader.getLength(); // IP Header length
        int offset = this.tcpHeader.getOffset(); // TCP Header length
        int position = length + offset;
        this.buffer.position(position);
        this.buffer.put(bytes);
    }

    public void checksum() {
        this.ipHeader.setChecksum((short) this.ipHeader.checksum());
        this.tcpHeader.setChecksum((short) this.tcpHeader.checksum());
    }
}
