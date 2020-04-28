package org.pcap4j.packet.namednumber.tls;

import org.pcap4j.packet.namednumber.NamedNumber;

import java.util.HashMap;
import java.util.Map;

public class ContentType extends NamedNumber<Byte, ContentType> {

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

    public static final ContentType CHANGE_CIPHER_SPEC = new ContentType((byte) 20, "Change Cipher Spec");
    public static final ContentType ALERT = new ContentType((byte) 21, "Alert");
    public static final ContentType HANDSHAKE = new ContentType((byte) 22, "Handshake");
    public static final ContentType APPLICATION_DATA = new ContentType((byte) 23, "Application Data");
    public static final ContentType HEARTBEAT = new ContentType((byte) 24, "Heartbeat");

    private static final Map<Byte, ContentType> registry = new HashMap<>();

    static {
        registry.put(CHANGE_CIPHER_SPEC.value(), CHANGE_CIPHER_SPEC);
        registry.put(ALERT.value(), ALERT);
        registry.put(HANDSHAKE.value(), HANDSHAKE);
        registry.put(APPLICATION_DATA.value(), APPLICATION_DATA);
        registry.put(HEARTBEAT.value(), HEARTBEAT);
    }

    public ContentType(Byte value, String name) {
        super(value, name);
    }

    public static ContentType getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            throw new IllegalArgumentException("Unknown record type " + value);
        }
    }

    @Override
    public int compareTo(ContentType o) {
        return value().compareTo(o.value());
    }
}
