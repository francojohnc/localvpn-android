package com.innque.localvpn;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class IP4Header {
    public static final int SIZE = 20; // IP header size

    public byte version;
    public byte IHL;
    public int headerLength;
    public short typeOfService;
    public int totalLength;

    public int identificationAndFlagsAndFragmentOffset;

    public short TTL;
    private short protocolNum;
    public TransportProtocol protocol;
    public int headerChecksum;

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

    public IP4Header(ByteBuffer buffer) throws UnknownHostException {
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

    public void setTotalLength(int totalLength) {
        this.buffer.putShort(2, (short) totalLength);
    }

    public void setChecksum(int checksum) {
        this.buffer.putShort(0, (short) checksum);
    }

    // get calculated checksum
    public int checksum() {
        ByteBuffer buffer = this.buffer.duplicate();
        int length = IP4Header.SIZE;
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
}