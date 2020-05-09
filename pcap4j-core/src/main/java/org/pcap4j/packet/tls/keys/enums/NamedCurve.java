package org.pcap4j.packet.tls.keys.enums;

import java.util.HashMap;
import java.util.Map;

public enum NamedCurve {

    SECT163K1((short) 1),
    SECT163R1((short) 2),
    SECT163R2((short) 3),
    SECT193R1((short) 4),
    SECT193R2((short) 5),
    SECT233K1((short) 6),
    SECT233R1((short) 7),
    SECT239K1((short) 8),
    SECT283K1((short) 9),
    SECT283R1((short) 10),
    SECT409K1((short) 11),
    SECT409R1((short) 12),
    SECT571K1((short) 13),
    SECT571R1((short) 14),
    SECP160K1((short) 15),
    SECP160R1((short) 16),
    SECP160R2((short) 17),
    SECP192K1((short) 18),
    SECP192R1((short) 19),
    SECP224K1((short) 20),
    SECP224R1((short) 21),
    SECP256K1((short) 22),
    SECP256R1((short) 23),
    SECP384R1((short) 24),
    SECP521R1((short) 25),
    X25519((short) 29),
    X448((short) 30);

    private final short value;

    private static final Map<Short, NamedCurve> map = new HashMap<Short, NamedCurve>();

    NamedCurve(short value) {
        this.value = value;
    }

    static {
        for (NamedCurve curve : values()) {
            map.put(curve.getValue(), curve);
        }
    }

    public short getValue() {
        return value;
    }

    public static NamedCurve findByValue(short value) {
        return map.get(value);
    }
}
