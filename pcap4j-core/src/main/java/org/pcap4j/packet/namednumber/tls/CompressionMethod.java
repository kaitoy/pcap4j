package org.pcap4j.packet.namednumber.tls;

import org.pcap4j.packet.namednumber.NamedNumber;

import java.util.HashMap;
import java.util.Map;

public class CompressionMethod extends NamedNumber<Byte, CompressionMethod> {

    // https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml

    public static final CompressionMethod NULL = new CompressionMethod((byte) 0, "null");
    public static final CompressionMethod DEFLATE = new CompressionMethod((byte) 1, "Deflate");
    public static final CompressionMethod LZS = new CompressionMethod((byte) 64, "LZS");

    private static final Map<Byte, CompressionMethod> registry = new HashMap<Byte, CompressionMethod>();

    static {
        registry.put(NULL.value(), NULL);
    }

    public CompressionMethod(Byte value, String name) {
        super(value, name);
    }

    public static CompressionMethod getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new CompressionMethod(value, "Unknown");
        }
    }

    @Override
    public int compareTo(CompressionMethod o) {
        return value().compareTo(o.value());
    }
}
