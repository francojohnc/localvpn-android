package com.innque.localvpn;

import java.nio.ByteBuffer;

public class TCPHeader {
    public static final int SIZE = 20; // tcp header size

    public static final int FIN = 0x01;
    public static final int SYN = 0x02;
    public static final int RST = 0x04;
    public static final int PSH = 0x08;
    public static final int ACK = 0x10;
    public static final int URG = 0x20;

    public int sourcePort;
    public int destinationPort;

    public long sequenceNumber;
    public long acknowledgementNumber;

    public byte dataOffsetAndReserved;
    public int headerLength;
    public byte flags;
    public int window;

    public int checksum;
    public int urgentPointer;

    public byte[] optionsAndPadding;
    private ByteBuffer buffer;
    private IP4Header ipHeader;

    public TCPHeader(ByteBuffer buffer, IP4Header ipHeader) {
        this.buffer = buffer;
        this.ipHeader = ipHeader;
        this.sourcePort = BitUtils.getUnsignedShort(buffer.getShort());
        this.destinationPort = BitUtils.getUnsignedShort(buffer.getShort());

        this.sequenceNumber = BitUtils.getUnsignedInt(buffer.getInt());
        this.acknowledgementNumber = BitUtils.getUnsignedInt(buffer.getInt());

        this.dataOffsetAndReserved = buffer.get();
        this.headerLength = (this.dataOffsetAndReserved & 0xF0) >> 2;
        this.flags = buffer.get();
        this.window = BitUtils.getUnsignedShort(buffer.getShort());

        this.checksum = BitUtils.getUnsignedShort(buffer.getShort());
        this.urgentPointer = BitUtils.getUnsignedShort(buffer.getShort());

        int optionsLength = this.headerLength - TCPHeader.SIZE;
        if (optionsLength > 0) {
            optionsAndPadding = new byte[optionsLength];
            buffer.get(optionsAndPadding, 0, optionsLength);
        }
    }

    public boolean isFIN() {
        return (flags & FIN) == FIN;
    }

    public boolean isSYN() {
        return (flags & SYN) == SYN;
    }

    public boolean isRST() {
        return (flags & RST) == RST;
    }

    public boolean isPSH() {
        return (flags & PSH) == PSH;
    }

    public boolean isACK() {
        return (flags & ACK) == ACK;
    }

    public boolean isURG() {
        return (flags & URG) == URG;
    }

    public void fillHeader() {
        this.buffer.putShort((short) sourcePort);
        this.buffer.putShort((short) destinationPort);

        this.buffer.putInt((int) sequenceNumber);
        this.buffer.putInt((int) acknowledgementNumber);

        this.buffer.put(dataOffsetAndReserved);
        this.buffer.put(flags);
        this.buffer.putShort((short) window);

        this.buffer.putShort((short) checksum);
        this.buffer.putShort((short) urgentPointer);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("TCPHeader{");
        sb.append("sourcePort:").append(sourcePort);
        sb.append(",destinationPort:").append(destinationPort);
        sb.append(",sequenceNumber:").append(sequenceNumber);
        sb.append(",acknowledgementNumber:").append(acknowledgementNumber);
        sb.append(",offset:").append(headerLength);
        if (isFIN()) sb.append(",FIN:").append(true);
        if (isSYN()) sb.append(",SYN:").append(true);
        if (isRST()) sb.append(",RST:").append(true);
        if (isPSH()) sb.append(",PSH:").append(true);
        if (isACK()) sb.append(",ACK:").append(true);
        if (isURG()) sb.append(",URG:").append(true);
        sb.append(",window:").append(window);
        sb.append(",checksum:").append(checksum);
        sb.append('}');
        return sb.toString();
    }

    public void setFlags(byte flags) {
        this.buffer.put(IP4Header.SIZE + 13, flags);
    }

    public void setSequenceNumber(long sequenceNumber) {
        this.buffer.putInt(IP4Header.SIZE + 4, (int) sequenceNumber);
    }

    public void setAcknowledgmentNumber(long acknowledgmentNumber) {
        this.buffer.putInt(IP4Header.SIZE + 8, (int) acknowledgmentNumber);
    }

    public void setOffset(byte offset) {
        this.buffer.put(IP4Header.SIZE + 12, offset);
    }

    // get calculated checksum
    public int checksum(int payloadSize) {
        // IP Header
        byte[] sourceAddress = this.ipHeader.sourceAddress.getAddress();
        byte[] destinationAddress = this.ipHeader.destinationAddress.getAddress();


        int ipLength = IP4Header.SIZE;
        int totalLength = TCPHeader.SIZE + payloadSize;
        short protocol = 6;
        // TCP Header
        int tcpLength = TCPHeader.SIZE; // TCP Header length
        // Data
        int offset = ipLength + tcpLength; // beginning position of data
        int size = totalLength - offset; // size of data
        // PSEUDO Header
        int pseudoLength = 12;
        ByteBuffer pseudo = ByteBuffer.allocate(pseudoLength);
        pseudo.put(sourceAddress);
        pseudo.put(destinationAddress);
        pseudo.put((byte) 0x0); // reserve
        pseudo.put((byte) protocol); // stores the protocol number
        pseudo.putChar((char) (tcpLength + size)); // store the length of the packet.
        // sum pseudo-header
        int sum = 0;
        pseudo.position(0);
        while (pseudoLength > 0) {
            sum += BitUtils.getUnsignedShort(pseudo.getShort());
            pseudoLength -= 2;
        }
        // sum tcp-header
        // clear the previous checksum
        this.setChecksum((short) 0);
        this.buffer.position(ipLength);
        while (tcpLength > 0) {
            sum += BitUtils.getUnsignedShort(this.buffer.getShort());
            tcpLength -= 2;
        }
//        // sum data
//        while (size > 0) {
//            sum += BitUtils.getUnsignedShort(this.buffer.getShort());
//            size -= 2;
//        }
//        // if data size is odd
//        if (size > 0) {
//            sum += BitUtils.getUnsignedByte(buffer.get()) << 8;
//        }
        return (int) BitUtils.checksum(sum, 16);
    }

    public void setChecksum(int checksum) {
        this.buffer.putShort(IP4Header.SIZE + 16, (short) checksum);
    }
}