package com.innque.localvpn;

import java.nio.ByteBuffer;

public class TCPHeader {
    public static final int TCP_HEADER_SIZE = 20;
    // flags
    public static final byte FIN = 1;  // 000001
    public static final byte SYN = 2;  // 000010
    public static final byte RST = 4;  // 000100
    public static final byte PSH = 8;  // 001000
    public static final byte ACK = 16; // 010000
    public static final byte URG = 32; // 100000
    private ByteBuffer buffer;
    private IPHeader ipHeader;

    public TCPHeader(ByteBuffer buffer, IPHeader ipHeader) {
        this.buffer = buffer;
        this.ipHeader = ipHeader;
    }

    public void setSourcePort(short sourcePort) {
        this.buffer.position(this.ipHeader.getLength());
        this.buffer.putShort(sourcePort);
    }

    public int getSourcePort() {
        this.buffer.position(this.ipHeader.getLength());
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void setDestinationPort(short destinationPort) {
        this.buffer.position(this.ipHeader.getLength() + 2);
        this.buffer.putShort(destinationPort);
    }

    public int getDestinationPort() {
        this.buffer.position(this.ipHeader.getLength() + 2);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.buffer.position(this.ipHeader.getLength() + 4);
        this.buffer.putInt(sequenceNumber);
    }

    public long getSequenceNumber() {
        this.buffer.position(this.ipHeader.getLength() + 4);
        return BitUtils.getUnsignedInt(buffer.getInt());
    }

    public void setAcknowledgmentNumber(int acknowledgmentNumber) {
        this.buffer.position(this.ipHeader.getLength() + 8);
        this.buffer.putInt(acknowledgmentNumber);
    }

    public long getAcknowledgmentNumber() {
        this.buffer.position(this.ipHeader.getLength() + 8);
        return BitUtils.getUnsignedInt(buffer.getInt());
    }


    public void setOffset(int offset) {
        this.buffer.position(this.ipHeader.getLength() + 12);
        this.buffer.put((byte) ((offset / 4) << 4));
    }

    public int getOffset() {
        this.buffer.position(this.ipHeader.getLength() + 12);
        short offsetAndReserved = BitUtils.getUnsignedByte(buffer.get());
        return (offsetAndReserved >> 4) * 4;
    }

    public void setReserve(byte reserve) {
        this.buffer.position(this.ipHeader.getLength() + 12);
        short offsetAndReserved = BitUtils.getUnsignedByte(buffer.get());
        this.buffer.position(this.ipHeader.getLength() + 12);
        this.buffer.put((byte) (offsetAndReserved + reserve));
    }

    public byte getReserve() {
        this.buffer.position(this.ipHeader.getLength() + 12);
        short offsetAndReserved = BitUtils.getUnsignedByte(buffer.get());
        return (byte) (offsetAndReserved & 0b1111);
    }

    public void setFlags(byte flags) {
        this.buffer.position(this.ipHeader.getLength() + 13);
        this.buffer.put(flags);
    }

    public byte getFlags() {
        this.buffer.position(this.ipHeader.getLength() + 13);
        return this.buffer.get();
    }

    public void setWindow(short window) {
        this.buffer.position(this.ipHeader.getLength() + 14);
        this.buffer.putShort(window);
    }

    public int getWindow() {
        this.buffer.position(this.ipHeader.getLength() + 14);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void setChecksum(short checksum) {
        this.buffer.position(this.ipHeader.getLength() + 16);
        this.buffer.putShort(checksum);
    }

    public int getChecksum() {
        this.buffer.position(this.ipHeader.getLength() + 16);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void setUrgentPointer(short urgentPointer) {
        this.buffer.position(this.ipHeader.getLength() + 18);
        this.buffer.putShort(urgentPointer);
    }

    public int getUrgentPointer() {
        this.buffer.position(this.ipHeader.getLength() + 18);
        return BitUtils.getUnsignedShort(buffer.getShort());
    }

    public byte[] getOptionsAndPadding() {
        this.buffer.position(this.ipHeader.getLength() + 19);
        int optionsLength = this.getOffset() - TCP_HEADER_SIZE;
        byte[] optionsAndPadding = new byte[0];
        if (optionsLength > 0) {
            optionsAndPadding = new byte[optionsLength];
            buffer.get(optionsAndPadding, 0, optionsLength);
        }
        return optionsAndPadding;
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


    public void swapPort() {
        int source = this.getSourcePort();
        int destination = this.getDestinationPort();
        this.setDestinationPort((short) source);
        this.setSourcePort((short) destination);
    }


    // get calculated checksum
    public int checksum() {
        // IP Header
        byte[] sourceAddress = this.ipHeader.getSourceAddressRaw();
        byte[] destinationAddress = this.ipHeader.getDestinationAddressRaw();
        int ipLength = this.ipHeader.getLength();
        int totalLength = this.ipHeader.getTotalLength();
        short protocol = this.ipHeader.getProtocol();
        // TCP Header
        int tcpLength = this.getOffset(); // TCP Header length
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
        // sum data
        while (size > 0) {
            sum += BitUtils.getUnsignedShort(this.buffer.getShort());
            size -= 2;
        }
        // if data size is odd
        if (size > 0) {
            sum += BitUtils.getUnsignedByte(buffer.get()) << 8;
        }
        return (int) BitUtils.checksum(sum, 16);
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
