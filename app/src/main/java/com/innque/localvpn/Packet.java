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
        this.buffer = buffer;
        this.ipHeader = new IP4Header(buffer);
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
//        tcpHeader.setChecksum(tcpHeader.checksum(payloadSize));

        int ip4TotalLength = IP4Header.SIZE + TCPHeader.SIZE + payloadSize;
        ipHeader.totalLength = ip4TotalLength;
        ipHeader.setTotalLength(ip4TotalLength);
        ipHeader.setChecksum(ipHeader.checksum());
    }

    private void updateTCPChecksum(int payloadSize) {
        int sum;
        int tcpLength = TCPHeader.SIZE + payloadSize;

        // // PSEUDO Header
        ByteBuffer buffer = ByteBuffer.wrap(ipHeader.sourceAddress.getAddress());
        sum = BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        buffer = ByteBuffer.wrap(ipHeader.destinationAddress.getAddress());
        sum += BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        sum += IP4Header.TransportProtocol.TCP.getNumber() + tcpLength;

        buffer = this.buffer.duplicate();
        // clear the previous checksum
        tcpHeader.setChecksum(0);

        // sum tcp-header
        buffer.position(IP4Header.SIZE);
        while (tcpLength > 1) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            tcpLength -= 2;
        }
        // if data size is odd
        if (tcpLength > 0) {
            sum += BitUtils.getUnsignedByte(buffer.get()) << 8;
        }
        tcpHeader.setChecksum((int) BitUtils.checksum(sum, 16));
    }

    private void fillHeader() {
        ipHeader.fillHeader();
        tcpHeader.fillHeader();
    }


}
