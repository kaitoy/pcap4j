package org.pcap4j.packet.tls.keys.enums;

import java.util.HashMap;
import java.util.Map;

public enum SignatureScheme {

    /* RSASSA-PKCS1-v1_5 algorithms */
    RSA_PKCS1_SHA256((short) 0x0401),
    RSA_PKCS1_SHA384((short) 0x0501),
    RSA_PKCS1_SHA512((short) 0x0601),

    /* ECDSA algorithms */
    ECDSA_SECP256R1_SHA256((short) 0x0403),
    ECDSA_SECP384R1_SHA384((short) 0x0503),
    ECDSA_SECP521R1_SHA512((short) 0x0603),

    /* RSASSA-PSS algorithms with public key OID RSAEncryption */
    RSA_PSS_RSAE_SHA256((short) 0x0804),
    RSA_PSS_RSAE_SHA384((short) 0x0805),
    RSA_PSS_RSAE_SHA512((short) 0x0806),

    /* EDDSA algorithms */
    ED25519((short) 0x0807),
    ED448((short) 0x0808),

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RSA_PSS_PSS_SHA256((short) 0x0809),
    RSA_PSS_PSS_SHA384((short) 0x080a),
    RSA_PSS_PSS_SHA512((short) 0x080b),

    /* Legacy algorithms */
    RSA_PKCS1_SHA1((short) 0x0201),
    ECDSA_SHA1((short) 0x0203);

    private final short value;

    private static final Map<Short, SignatureScheme> map = new HashMap<Short, SignatureScheme>();

    SignatureScheme(short value) {
        this.value = value;
    }

    static {
        for (SignatureScheme curve : values()) {
            map.put(curve.getValue(), curve);
        }
    }

    public short getValue() {
        return value;
    }

    public static SignatureScheme findByValue(short value) {
        return map.get(value);
    }

}
