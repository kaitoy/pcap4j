package org.pcap4j.packet.namednumber.tls;

import org.pcap4j.packet.namednumber.NamedNumber;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class AlertLevel extends NamedNumber<Byte, AlertLevel> {

    private static final Map<Byte, AlertLevel> registry = new HashMap<>();

    public static final AlertLevel WARNING = new AlertLevel((byte) 1, "warning");
    public static final AlertLevel FATAL = new AlertLevel((byte) 2, "fatal");

    public AlertLevel(Byte value, String name) {
        super(value, name);
        registry.put(value, this);
    }

    public static AlertLevel getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            throw new IllegalArgumentException("Unknown alert level: " + value);
        }
    }

    @Override
    public int compareTo(AlertLevel o) {
        return value().compareTo(o.value());
    }

}
