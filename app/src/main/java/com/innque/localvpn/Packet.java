package com.innque.localvpn;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Representation Packet
 */

public class Packet {

    public IP4Header ipHeader;
    public TCPHeader tcpHeader;
    public ByteBuffer buffer;


    public Packet(ByteBuffer buffer) throws UnknownHostException {
        this.ipHeader = new IP4Header(buffer);
        this.tcpHeader = new TCPHeader(buffer);
        this.buffer = buffer;
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
        tcpHeader.flags = flags;
        this.tcpHeader.setFlags(flags);
        tcpHeader.sequenceNumber = sequenceNum;
        this.tcpHeader.setSequenceNumber(sequenceNum);

        tcpHeader.acknowledgementNumber = ackNum;
        this.tcpHeader.setAcknowledgmentNumber(ackNum);

        // Reset header size, since we don't need options
        byte dataOffset = (byte) (TCPHeader.SIZE << 2);
        tcpHeader.dataOffsetAndReserved = dataOffset;
        this.tcpHeader.setOffset(dataOffset);

        updateTCPChecksum(payloadSize);

        int ip4TotalLength = IP4Header.SIZE + TCPHeader.SIZE + payloadSize;
        ipHeader.totalLength = ip4TotalLength;
        ipHeader.setTotalLength(ip4TotalLength);
        ipHeader.setChecksum(ipHeader.checksum());
    }

    private void updateTCPChecksum(int payloadSize) {
        int sum = 0;
        int tcpLength = TCPHeader.SIZE + payloadSize;

        // Calculate pseudo-header checksum
        ByteBuffer buffer = ByteBuffer.wrap(ipHeader.sourceAddress.getAddress());
        sum = BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        buffer = ByteBuffer.wrap(ipHeader.destinationAddress.getAddress());
        sum += BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        sum += IP4Header.TransportProtocol.TCP.getNumber() + tcpLength;

        buffer = this.buffer.duplicate();
        // Clear previous checksum
        buffer.putShort(IP4Header.SIZE + 16, (short) 0);

        // Calculate TCP segment checksum
        buffer.position(IP4Header.SIZE);
        while (tcpLength > 1) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            tcpLength -= 2;
        }
        if (tcpLength > 0)
            sum += BitUtils.getUnsignedByte(buffer.get()) << 8;

        while (sum >> 16 > 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        sum = ~sum;
        tcpHeader.checksum = sum;
        this.buffer.putShort(IP4Header.SIZE + 16, (short) sum);
    }

    private void fillHeader() {
        ipHeader.fillHeader();
        tcpHeader.fillHeader();
    }


}
