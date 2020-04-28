package org.pcap4j.packet.tls.extensions;

import org.pcap4j.packet.namednumber.tls.ExtensionType;
import org.pcap4j.util.ByteArrays;

import java.util.Arrays;

public class UnimplementedTlsExtension extends TlsExtension {

    private byte[] data;

    public UnimplementedTlsExtension(ExtensionType type, byte[] rawData, int offset, short extensionLength) {
        super(type, extensionLength);

        data = new byte[extensionLength];
        System.arraycopy(rawData, offset, data, 0, extensionLength);
    }

    @Override
    public String toString() {
        if(extensionLength > 0) {
            return type.name() + " [" + extensionLength + " bytes]";
        } else {
            return type.name();
        }
    }

    @Override
    public byte[] toByteArray() {
        return ByteArrays.concatenate(Arrays.asList(
                ByteArrays.toByteArray(type.value()),
                ByteArrays.toByteArray(extensionLength),
                data
        ));
    }
}
