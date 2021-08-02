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

    //    public int sourcePort;
//    public int destinationPort;
//
//    public long sequenceNumber;
//    public long acknowledgementNumber;
//
//    public byte dataOffsetAndReserved;
//    public int headerLength;
//    public byte flags;
//    public int window;
//
//    public int checksum;
//    public int urgentPointer;
//
//    public byte[] optionsAndPadding;
    private ByteBuffer buffer;
    private IPHeader ipHeader;

    public TCPHeader(ByteBuffer buffer, IPHeader ipHeader) {
        this.buffer = buffer;
        this.ipHeader = ipHeader;
//        this.sourcePort = BitUtils.getUnsignedShort(buffer.getShort());
//        this.destinationPort = BitUtils.getUnsignedShort(buffer.getShort());
//
//        this.sequenceNumber = BitUtils.getUnsignedInt(buffer.getInt());
//        this.acknowledgementNumber = BitUtils.getUnsignedInt(buffer.getInt());
//
//        this.dataOffsetAndReserved = buffer.get();
//        this.headerLength = (this.dataOffsetAndReserved & 0xF0) >> 2;
//        this.flags = buffer.get();
//        this.window = BitUtils.getUnsignedShort(buffer.getShort());
//
//        this.checksum = BitUtils.getUnsignedShort(buffer.getShort());
//        this.urgentPointer = BitUtils.getUnsignedShort(buffer.getShort());
//
//        int optionsLength = this.headerLength - TCPHeader.SIZE;
//        if (optionsLength > 0) {
//            optionsAndPadding = new byte[optionsLength];
//            buffer.get(optionsAndPadding, 0, optionsLength);
//        }
    }

    public boolean isFIN() {
        return (this.getFlags() & FIN) == FIN;
    }

    public boolean isSYN() {
        return (this.getFlags() & SYN) == SYN;
    }

    public boolean isRST() {
        return (this.getFlags() & RST) == RST;
    }

    public boolean isPSH() {
        return (this.getFlags() & PSH) == PSH;
    }

    public boolean isACK() {
        return (this.getFlags() & ACK) == ACK;
    }

    public boolean isURG() {
        return (this.getFlags() & URG) == URG;
    }


//    public void fillHeader() {
//        this.buffer.putShort((short) sourcePort);
//        this.buffer.putShort((short) destinationPort);
//
//        this.buffer.putInt((int) sequenceNumber);
//        this.buffer.putInt((int) acknowledgementNumber);
//
//        this.buffer.put(dataOffsetAndReserved);
//        this.buffer.put(flags);
//        this.buffer.putShort((short) window);
//
//        this.buffer.putShort((short) checksum);
//        this.buffer.putShort((short) urgentPointer);
//    }

//    @Override
//    public String toString() {
//        StringBuilder sb = new StringBuilder("TCPHeader{");
//        sb.append("sourcePort:").append(sourcePort);
//        sb.append(",destinationPort:").append(destinationPort);
//        sb.append(",sequenceNumber:").append(sequenceNumber);
//        sb.append(",acknowledgementNumber:").append(acknowledgementNumber);
//        sb.append(",offset:").append(headerLength);
//        if (isFIN()) sb.append(",FIN:").append(true);
//        if (isSYN()) sb.append(",SYN:").append(true);
//        if (isRST()) sb.append(",RST:").append(true);
//        if (isPSH()) sb.append(",PSH:").append(true);
//        if (isACK()) sb.append(",ACK:").append(true);
//        if (isURG()) sb.append(",URG:").append(true);
//        sb.append(",window:").append(window);
//        sb.append(",checksum:").append(checksum);
//        sb.append('}');
//        return sb.toString();
//    }


    public void setSequenceNumber(long sequenceNumber) {
        this.buffer.putInt(IPHeader.SIZE + 4, (int) sequenceNumber);
    }

    public void setAcknowledgmentNumber(long acknowledgmentNumber) {
        this.buffer.putInt(IPHeader.SIZE + 8, (int) acknowledgmentNumber);
    }

    public void setOffset(byte offset) {
        this.buffer.put(IPHeader.SIZE + 12, offset);
    }

    // get calculated checksum
    public int checksum(int payloadSize) {
        int sum;
        int tcpLength = TCPHeader.SIZE + payloadSize;

        // // PSEUDO Header
        ByteBuffer buffer = ByteBuffer.wrap(ipHeader.getSourceAddress().getAddress());
        sum = BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        buffer = ByteBuffer.wrap(ipHeader.getDestinationAddress().getAddress());
        sum += BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        sum += this.ipHeader.getProtocol() + tcpLength;

        buffer = this.buffer.duplicate();
        // clear the previous checksum
        this.setChecksum(0);

        // sum tcp-header
        buffer.position(IPHeader.SIZE);
        while (tcpLength > 1) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            tcpLength -= 2;
        }
        // if data size is odd
        if (tcpLength > 0) {
            sum += BitUtils.getUnsignedByte(buffer.get()) << 8;
        }
        return (int) BitUtils.checksum(sum, 16);
    }

    public void setChecksum(int checksum) {
        this.buffer.putShort(IPHeader.SIZE + 16, (short) checksum);
    }


    public void setSourcePort(short sourcePort) {
        this.buffer.putShort(IPHeader.SIZE, sourcePort);
    }

    public int getSourcePort() {
        this.buffer.position(IPHeader.SIZE);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void setDestinationPort(short destinationPort) {
        this.buffer.putShort(IPHeader.SIZE + 2, destinationPort);
    }

    public int getDestinationPort() {
        this.buffer.position(IPHeader.SIZE + 2);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.buffer.putInt(IPHeader.SIZE + 4, sequenceNumber);
    }

    public long getSequenceNumber() {
        this.buffer.position(IPHeader.SIZE + 4);
        return BitUtils.getUnsignedInt(buffer.getInt());
    }

    public void setAcknowledgmentNumber(int acknowledgmentNumber) {
        this.buffer.putInt(IPHeader.SIZE + 8, acknowledgmentNumber);
    }

    public long getAcknowledgmentNumber() {
        this.buffer.position(IPHeader.SIZE + 8);
        return BitUtils.getUnsignedInt(buffer.getInt());
    }


    public void setOffset(int offset) {
        this.buffer.put(IPHeader.SIZE + 12, (byte) ((offset / 4) << 4));
    }

    public int getOffset() {
        this.buffer.position(IPHeader.SIZE + 12);
        short offsetAndReserved = BitUtils.getUnsignedByte(buffer.get());
        return (offsetAndReserved >> 4) * 4;
    }

    public void setReserve(byte reserve) {
        this.buffer.position(IPHeader.SIZE + 12);
        short offsetAndReserved = BitUtils.getUnsignedByte(buffer.get());
        this.buffer.put(IPHeader.SIZE + 12, (byte) (offsetAndReserved + reserve));
    }

    public byte getReserve() {
        this.buffer.position(IPHeader.SIZE + 12);
        short offsetAndReserved = BitUtils.getUnsignedByte(buffer.get());
        return (byte) (offsetAndReserved & 0b1111);
    }

    public void setFlags(byte flags) {
        this.buffer.put(IPHeader.SIZE + 13, flags);
    }

    public byte getFlags() {
        this.buffer.position(IPHeader.SIZE + 13);
        return this.buffer.get();
    }

    public void setWindow(short window) {
        this.buffer.putShort(IPHeader.SIZE + 14, window);
    }

    public int getWindow() {
        this.buffer.position(IPHeader.SIZE + 14);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }


    public int getChecksum() {
        this.buffer.position(IPHeader.SIZE + 16);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void setUrgentPointer(short urgentPointer) {
        this.buffer.putShort(IPHeader.SIZE + 18, urgentPointer);
    }

    public int getUrgentPointer() {
        this.buffer.position(IPHeader.SIZE + 18);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public byte[] getOptionsAndPadding() {
        this.buffer.position(IPHeader.SIZE + 19);
        int optionsLength = this.getOffset() - TCPHeader.SIZE;
        byte[] optionsAndPadding = new byte[0];
        if (optionsLength > 0) {
            optionsAndPadding = new byte[optionsLength];
            buffer.get(optionsAndPadding, 0, optionsLength);
        }
        return optionsAndPadding;
    }


    public void swapPort() {
        int source = this.getSourcePort();
        int destination = this.getDestinationPort();
        this.setDestinationPort((short) source);
        this.setSourcePort((short) destination);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("TCPHeader{");
        sb.append("sourcePort:").append(getSourcePort());
        sb.append(",destinationPort:").append(getDestinationPort());
        sb.append(",sequenceNumber:").append(getSequenceNumber());
        sb.append(",acknowledgementNumber:").append(getAcknowledgmentNumber());
        sb.append(",offset:").append(getOffset());
        sb.append(",flags:").append(getFlags());
        if (isFIN()) sb.append(",FIN:").append(true);
        if (isSYN()) sb.append(",SYN:").append(true);
        if (isRST()) sb.append(",RST:").append(true);
        if (isPSH()) sb.append(",PSH:").append(true);
        if (isACK()) sb.append(",ACK:").append(true);
        if (isURG()) sb.append(",URG:").append(true);
        sb.append(",window:").append(getWindow());
        sb.append(",checksum:").append(getChecksum());
        sb.append(",urgentPointer:").append(getUrgentPointer());
        sb.append('}');
        return sb.toString();
    }
}