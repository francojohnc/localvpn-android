package com.innque.localvpn;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class IPHeader {
    public static final int SIZE = 20; // IP header size

    private ByteBuffer buffer;

    public IPHeader(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    // get calculated checksum
    public int checksum() {
        ByteBuffer buffer = this.buffer.duplicate();
        int length = IPHeader.SIZE;
        // clear the previous checksum
        this.setChecksum((short) 0);
        buffer.position(0);
        int sum = 0;
        while (length > 0) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            length -= 2;
        }
        return (int) BitUtils.checksum(sum, 16);
    }

    public void setVersion(byte version) {
        this.buffer.put(0, (byte) (version << 4));
    }

    public byte getVersion() {
        this.buffer.position(0);
        byte versionAndHelen = this.buffer.get();
        return (byte) (versionAndHelen >> 4);
    }

    public void setLength(int length) {
        byte versionAndHelen = this.buffer.get();
        int IHL = length / 4;
        this.buffer.position(0);
        this.buffer.put(0, (byte) (versionAndHelen + IHL));
    }

    public int getLength() {
        this.buffer.position(0);
        short versionAndHelen = BitUtils.getUnsignedByte(this.buffer.get());
        int IHL = versionAndHelen & 0x0F;
        return IHL * 4;
    }

    public void setType(byte type) {
        this.buffer.put(1, type);
    }

    public short getType() {
        this.buffer.position(1);
        return BitUtils.getUnsignedByte(this.buffer.get());
    }

    public void setTotalLength(int totalLength) {
        this.buffer.putShort(2, (short) totalLength);
    }

    public int getTotalLength() {
        this.buffer.position(2);
        return BitUtils.getUnsignedShort(this.buffer.getShort());
    }

    public void setIdentification(short identification) {
        this.buffer.putShort(4, identification);
    }

    public int getIdentification() {
        this.buffer.position(4);
        return BitUtils.getUnsignedShort(this.buffer.getShort());
    }

    public void setFlags(byte flags) {
        short flagsAndOffset = (short) (flags << 13);
        this.buffer.putShort(6, flagsAndOffset);
    }

    public byte getFlags() {
        this.buffer.position(6);
        short flagsAndOffset = this.buffer.getShort();
        return (byte) (flagsAndOffset >> 13);
    }

    public void setOffset(short offset) {
        short flagsAndOffset = this.buffer.getShort();
        this.buffer.position(6);
        this.buffer.putShort(6, (short) (flagsAndOffset + offset));
    }

    public short getOffset() {
        this.buffer.position(6);
        short flagsAndOffset = this.buffer.getShort();
        return (short) (flagsAndOffset & 0x1FFF);
    }

    public void setTTL(byte TTL) {
        this.buffer.put(8, TTL);
    }

    public short getTTL() {
        this.buffer.position(8);
        return BitUtils.getUnsignedByte(this.buffer.get());
    }

    public void setProtocol(byte protocol) {
        this.buffer.put(9, protocol);
    }

    public short getProtocol() {
        this.buffer.position(9);
        return BitUtils.getUnsignedByte(this.buffer.get());
    }

    public void setChecksum(int checksum) {
        this.buffer.putShort(10, (short) checksum);
    }

    public int getChecksum() {
        this.buffer.position(10);
        return BitUtils.getUnsignedShort(this.buffer.getShort());
    }

    public void setSourceAddress(InetAddress sourceAddress) {
        this.buffer.position(12);
        this.buffer.put(sourceAddress.getAddress());
    }

    public byte[] getSourceAddressRaw() {
        ByteBuffer buffer = this.buffer.duplicate();
        buffer.position(12);
        byte[] addressBytes = new byte[4];
        buffer.get(addressBytes);
        return addressBytes;
    }

    public InetAddress getSourceAddress() {
        try {
            return InetAddress.getByAddress(this.getSourceAddressRaw());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void setDestinationAddress(InetAddress destinationAddress) {
        this.buffer.position(16);
        this.buffer.put(destinationAddress.getAddress());
    }

    public byte[] getDestinationAddressRaw() {
        ByteBuffer buffer = this.buffer.duplicate();
        buffer.position(16);
        byte[] addressBytes = new byte[4];
        buffer.get(addressBytes);
        return addressBytes;
    }

    public InetAddress getDestinationAddress() {
        try {
            return InetAddress.getByAddress(this.getDestinationAddressRaw());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void swapAddress() {
        InetAddress source = this.getSourceAddress();
        InetAddress destination = this.getDestinationAddress();
        this.setDestinationAddress(source);
        this.setSourceAddress(destination);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("IPHeader{");
        sb.append("version:").append(getVersion());
        sb.append(",length:").append(getLength());
        sb.append(",type:").append(getType());
        sb.append(",totalLength:").append(getTotalLength());
        sb.append(",identification:").append(getIdentification());
        sb.append(",flags:").append(getFlags());
        sb.append(",offset:").append(getOffset());
        sb.append(",ttl:").append(getTTL());
        sb.append(",protocol:").append(getProtocol());
        sb.append(",checksum:").append(getChecksum());
        sb.append(",sourceAddress:").append('"' + getSourceAddress().getHostAddress() + '"');
        sb.append(",destinationAddress:").append('"' + getDestinationAddress().getHostAddress() + '"');
        sb.append("}");
        return sb.toString();
    }
}