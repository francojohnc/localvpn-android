package com.innque.localvpn;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Representation Packet
 */

public class Packet {

    public IPHeader ipHeader;
    public TCPHeader tcpHeader;
    public ByteBuffer buffer;


    public Packet(ByteBuffer buffer) throws UnknownHostException {
        this.buffer = buffer;
        this.ipHeader = new IPHeader(buffer);
        this.tcpHeader = new TCPHeader(buffer, this.ipHeader);
    }


    public void swapSourceAndDestination() {
        InetAddress newSourceAddress = ipHeader.destinationAddress;
        ipHeader.destinationAddress = ipHeader.sourceAddress;
        ipHeader.sourceAddress = newSourceAddress;
        int newSourcePort = tcpHeader.destinationPort;
        tcpHeader.destinationPort = tcpHeader.sourcePort;
        tcpHeader.sourcePort = newSourcePort;
    }

    public void updateTCPBuffer(byte flags, long sequenceNum, long ackNum, int payloadSize) {
        this.buffer.position(0);
        fillHeader();
        this.tcpHeader.setFlags(flags);
        this.tcpHeader.setSequenceNumber(sequenceNum);
        this.tcpHeader.setAcknowledgmentNumber(ackNum);
        // Reset header size, since we don't need options
        byte dataOffset = (byte) (TCPHeader.SIZE << 2);
        this.tcpHeader.setOffset(dataOffset);
        this.tcpHeader.setChecksum(this.tcpHeader.checksum(payloadSize));
        int ip4TotalLength = IPHeader.SIZE + TCPHeader.SIZE + payloadSize;
        ipHeader.setTotalLength(ip4TotalLength);
        ipHeader.setChecksum(ipHeader.checksum());
    }


    private void fillHeader() {
        ipHeader.fillHeader();
        tcpHeader.fillHeader();
    }


}
