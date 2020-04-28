package org.pcap4j.packet.tls.extensions;

import org.pcap4j.packet.namednumber.tls.ExtensionType;
import org.pcap4j.packet.tls.extensions.keyshare.KeyShareExtension;
import org.pcap4j.util.ByteArrays;

public abstract class TlsExtension {

    /*
    0x0        - Type
    0x2        - Length
    0x4        - Content
    0x4+length - End
     */

    protected ExtensionType type;
    protected short extensionLength;

    public static TlsExtension newInstance(ExtensionType type, byte[] rawData, int offset,
                                           short extensionLength, boolean client) {
        if (extensionLength > 0) {
            ByteArrays.validateBounds(rawData, offset, extensionLength);
        }

        if (type == ExtensionType.KEY_SHARE) {
            return KeyShareExtension.newInstance(type, rawData, offset, extensionLength, client);
        } else {
            return new UnimplementedTlsExtension(type, rawData, offset, extensionLength);
        }
    }

    public TlsExtension(ExtensionType type, short extensionLength) {
        this.type = type;
        this.extensionLength = extensionLength;
    }

    public ExtensionType getType() {
        return type;
    }

    public short getLength() {
        return extensionLength;
    }

    @Override
    public String toString() {
        return type.name();
    }
}
