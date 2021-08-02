package com.innque.localvpn;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class IPHeader {
    public static final int SIZE = 20; // IP header size

    private byte version;
    private byte IHL;
    private int headerLength;
    private short typeOfService;
    private int totalLength;

    private int identificationAndFlagsAndFragmentOffset;

    private short TTL;
    private short protocolNum;
    private TransportProtocol protocol;
    private int headerChecksum;

    public InetAddress sourceAddress;
    public InetAddress destinationAddress;

    public enum TransportProtocol {
        TCP(6),
        UDP(17),
        Other(0xFF);

        private int protocolNumber;

        TransportProtocol(int protocolNumber) {
            this.protocolNumber = protocolNumber;
        }

        private static TransportProtocol numberToEnum(int protocolNumber) {
            if (protocolNumber == 6)
                return TCP;
            else if (protocolNumber == 17)
                return UDP;
            else
                return Other;
        }

        public int getNumber() {
            return this.protocolNumber;
        }
    }

    private ByteBuffer buffer;

    public IPHeader(ByteBuffer buffer) throws UnknownHostException {
        this.buffer = buffer;
        byte versionAndIHL = buffer.get();
        this.version = (byte) (versionAndIHL >> 4);
        this.IHL = (byte) (versionAndIHL & 0x0F);
        this.headerLength = this.IHL << 2;

        this.typeOfService = BitUtils.getUnsignedByte(buffer.get());
        this.totalLength = BitUtils.getUnsignedShort(buffer.getShort());

        this.identificationAndFlagsAndFragmentOffset = buffer.getInt();

        this.TTL = BitUtils.getUnsignedByte(buffer.get());
        this.protocolNum = BitUtils.getUnsignedByte(buffer.get());
        this.protocol = TransportProtocol.numberToEnum(protocolNum);
        this.headerChecksum = BitUtils.getUnsignedShort(buffer.getShort());

        byte[] addressBytes = new byte[4];
        buffer.get(addressBytes, 0, 4);
        this.sourceAddress = InetAddress.getByAddress(addressBytes);

        buffer.get(addressBytes, 0, 4);
        this.destinationAddress = InetAddress.getByAddress(addressBytes);
    }

    public void fillHeader() {
        this.buffer.put((byte) (this.version << 4 | this.IHL));
        this.buffer.put((byte) this.typeOfService);
        this.buffer.putShort((short) this.totalLength);

        this.buffer.putInt(this.identificationAndFlagsAndFragmentOffset);

        this.buffer.put((byte) this.TTL);
        this.buffer.put((byte) this.protocol.getNumber());
        this.buffer.putShort((short) this.headerChecksum);

        this.buffer.put(this.sourceAddress.getAddress());
        this.buffer.put(this.destinationAddress.getAddress());
//        this.setDestinationAddress(this.destinationAddress);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IP4Header{");
        sb.append("version=").append(version);
        sb.append(", IHL=").append(IHL);
        sb.append(", typeOfService=").append(typeOfService);
        sb.append(", totalLength=").append(totalLength);
        sb.append(", identificationAndFlagsAndFragmentOffset=").append(identificationAndFlagsAndFragmentOffset);
        sb.append(", TTL=").append(TTL);
        sb.append(", protocol=").append(protocolNum).append(":").append(protocol);
        sb.append(", headerChecksum=").append(headerChecksum);
        sb.append(", sourceAddress=").append(sourceAddress.getHostAddress());
        sb.append(", destinationAddress=").append(destinationAddress.getHostAddress());
        sb.append('}');
        return sb.toString();
    }

//    public void setTotalLength(int totalLength) {
//        this.buffer.putShort(2, (short) totalLength);
//    }
//
//    public void setChecksum(int checksum) {
//        this.buffer.putShort(10, (short) checksum);
//    }

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
//        this.buffer.put(12, sourceAddress.getAddress());
    }

    public byte[] getSourceAddressRaw() {
        this.buffer.position(12);
        byte[] addressBytes = new byte[4];
        this.buffer.get(addressBytes);
        return addressBytes;
    }

    public InetAddress getSourceAddress() throws UnknownHostException {
        return InetAddress.getByAddress(this.getSourceAddressRaw());
    }

    public void setDestinationAddress(InetAddress destinationAddress) {
//        this.buffer.put(16, destinationAddress.getAddress());
    }

    public byte[] getDestinationAddressRaw() {
        this.buffer.position(16);
        byte[] addressBytes = new byte[4];
        this.buffer.get(addressBytes);
        return addressBytes;
    }

    public InetAddress getDestinationAddress() throws UnknownHostException {
        return InetAddress.getByAddress(this.getDestinationAddressRaw());
    }

    public void swapAddress() throws UnknownHostException {
        InetAddress source = this.getSourceAddress();
        InetAddress destination = this.getDestinationAddress();
        this.setDestinationAddress(source);
        this.setSourceAddress(destination);
    }


}