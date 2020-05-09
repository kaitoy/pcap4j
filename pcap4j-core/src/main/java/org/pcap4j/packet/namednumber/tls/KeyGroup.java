package org.pcap4j.packet.namednumber.tls;

import org.pcap4j.packet.namednumber.NamedNumber;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class KeyGroup extends NamedNumber<Short, KeyGroup> {

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

    private static final Map<Short, KeyGroup> registry = new HashMap<Short, KeyGroup>();

    public static final KeyGroup RESERVED_GREASE_0 = new KeyGroup((short) 0, "Reserved (GREASE)");
    public static final KeyGroup SECT163K1 = new KeyGroup((short) 1, "sect163k1");
    public static final KeyGroup SECT163R1 = new KeyGroup((short) 2, "sect163r1");
    public static final KeyGroup SECT163R2 = new KeyGroup((short) 3, "sect163r2");
    public static final KeyGroup SECT193R1 = new KeyGroup((short) 4, "sect193r1");
    public static final KeyGroup SECT193R2 = new KeyGroup((short) 5, "sect193r2");
    public static final KeyGroup SECT233K1 = new KeyGroup((short) 6, "sect233k1");
    public static final KeyGroup SECT233R1 = new KeyGroup((short) 7, "sect233r1");
    public static final KeyGroup SECT239K1 = new KeyGroup((short) 8, "sect239k1");
    public static final KeyGroup SECT283K1 = new KeyGroup((short) 9, "sect283k1");
    public static final KeyGroup SECT283R1 = new KeyGroup((short) 10, "sect283r1");
    public static final KeyGroup SECT409K1 = new KeyGroup((short) 11, "sect409k1");
    public static final KeyGroup SECT409R1 = new KeyGroup((short) 12, "sect409r1");
    public static final KeyGroup SECT571K1 = new KeyGroup((short) 13, "sect571k1");
    public static final KeyGroup SECT571R1 = new KeyGroup((short) 14, "sect571r1");
    public static final KeyGroup SECP160K1 = new KeyGroup((short) 15, "secp160k1");
    public static final KeyGroup SECP160R1 = new KeyGroup((short) 16, "secp160r1");
    public static final KeyGroup SECP160R2 = new KeyGroup((short) 17, "secp160r2");
    public static final KeyGroup SECP192K1 = new KeyGroup((short) 18, "secp192k1");
    public static final KeyGroup SECP192R1 = new KeyGroup((short) 19, "secp192r1");
    public static final KeyGroup SECP224K1 = new KeyGroup((short) 20, "secp224k1");
    public static final KeyGroup SECP224R1 = new KeyGroup((short) 21, "secp224r1");
    public static final KeyGroup SECP256K1 = new KeyGroup((short) 22, "secp256k1");
    public static final KeyGroup SECP256R1 = new KeyGroup((short) 23, "secp256r1");
    public static final KeyGroup SECP384R1 = new KeyGroup((short) 24, "secp384r1");
    public static final KeyGroup SECP521R1 = new KeyGroup((short) 25, "secp521r1");
    public static final KeyGroup BRAINPOOLP256R1 = new KeyGroup((short) 26, "brainpoolP256r1");
    public static final KeyGroup BRAINPOOLP384R1 = new KeyGroup((short) 27, "brainpoolP384r1");
    public static final KeyGroup BRAINPOOLP512R1 = new KeyGroup((short) 28, "brainpoolP512r1");
    public static final KeyGroup X25519 = new KeyGroup((short) 29, "x25519");
    public static final KeyGroup X448 = new KeyGroup((short) 30, "x448");
    public static final KeyGroup BRAINPOOLP256R1TLS13 = new KeyGroup((short) 31, "brainpoolP256r1tls13");
    public static final KeyGroup BRAINPOOLP384R1TLS13 = new KeyGroup((short) 32, "brainpoolP384r1tls13");
    public static final KeyGroup BRAINPOOLP512R1TLS13 = new KeyGroup((short) 33, "brainpoolP512r1tls13");
    public static final KeyGroup GC256A = new KeyGroup((short) 34, "GC256A");
    public static final KeyGroup GC256B = new KeyGroup((short) 35, "GC256B");
    public static final KeyGroup GC256C = new KeyGroup((short) 36, "GC256C");
    public static final KeyGroup GC256D = new KeyGroup((short) 37, "GC256D");
    public static final KeyGroup GC512A = new KeyGroup((short) 38, "GC512A");
    public static final KeyGroup GC512B = new KeyGroup((short) 39, "GC512B");
    public static final KeyGroup GC512C = new KeyGroup((short) 40, "GC512C");
    public static final KeyGroup CURVESM2 = new KeyGroup((short) 41, "curveSM2");
    public static final KeyGroup FFDHE2048 = new KeyGroup((short) 256, "ffdhe2048");
    public static final KeyGroup FFDHE3072 = new KeyGroup((short) 257, "ffdhe3072");
    public static final KeyGroup FFDHE4096 = new KeyGroup((short) 258, "ffdhe4096");
    public static final KeyGroup FFDHE6144 = new KeyGroup((short) 259, "ffdhe6144");
    public static final KeyGroup FFDHE8192 = new KeyGroup((short) 260, "ffdhe8192");
    public static final KeyGroup RESERVED_GREASE_2570 = new KeyGroup((short) 2570, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_6682 = new KeyGroup((short) 6682, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_10794 = new KeyGroup((short) 10794, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_14906 = new KeyGroup((short) 14906, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_19018 = new KeyGroup((short) 19018, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_23130 = new KeyGroup((short) 23130, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_27242 = new KeyGroup((short) 27242, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_31354 = new KeyGroup((short) 31354, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_35466 = new KeyGroup((short) 35466, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_39578 = new KeyGroup((short) 39578, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_43690 = new KeyGroup((short) 43690, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_47802 = new KeyGroup((short) 47802, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_51914 = new KeyGroup((short) 51914, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_56026 = new KeyGroup((short) 56026, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_60138 = new KeyGroup((short) 60138, "Reserved (GREASE)");
    public static final KeyGroup RESERVED_GREASE_64250 = new KeyGroup((short) 64250, "Reserved (GREASE)");
    public static final KeyGroup ARBITRARY_EXPLICIT_PRIME_CURVES = new KeyGroup((short) 65281, "arbitrary_explicit_prime_curves");
    public static final KeyGroup ARBITRARY_EXPLICIT_CHAR2_CURVES = new KeyGroup((short) 65282, "arbitrary_explicit_char2_curves");

    public KeyGroup(Short value, String name) {
        super(value, name);
        registry.put(value, this);
    }

    public static KeyGroup getInstance(Short value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new KeyGroup(value, "Unknown");
        }
    }

    @Override
    public int compareTo(KeyGroup o) {
        return value().compareTo(o.value());
    }
}
