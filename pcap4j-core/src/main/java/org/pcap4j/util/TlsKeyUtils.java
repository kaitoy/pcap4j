package org.pcap4j.util;

import org.pcap4j.packet.tls.keys.enums.CurveType;
import org.pcap4j.packet.tls.keys.enums.NamedCurve;
import org.pcap4j.packet.tls.keys.enums.SignatureScheme;

import java.nio.ByteBuffer;

/**
 * It is impossible to determine key format just by KeyExchange record,
 * so you can use this class when analyzing tls traffic.
 */
public final class TlsKeyUtils {

    // https://wiki.osdev.org/TLS_Handshake

    private TlsKeyUtils() {
    }

    public static DhClientParams parseServerDH(byte[] rawData, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(rawData).position(offset);

        short pLength = bb.getShort();
        byte[] p = new byte[pLength];
        bb.get(p);

        short gLength = bb.getShort();
        byte[] g = new byte[gLength];
        bb.get(g);

        short pubKeyLength = bb.getShort();
        byte[] pubKey = new byte[pubKeyLength];  // aka Ys
        bb.get(pubKey);

        SignatureScheme signatureScheme = SignatureScheme.findByValue(bb.getShort());

        if (signatureScheme == null) {
            throw new IllegalArgumentException("Unknown signature scheme");
        }

        short signatureLength = bb.getShort();
        byte[] signature = new byte[signatureLength];

        bb.get(signature);

        return new DhClientParams(p, g, pubKey, signatureScheme, signature);
    }

    /**
     * @param rawData Handshake record content
     */
    public static EcdheServerParams parseServerECDHE(byte[] rawData, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(rawData).position(offset);

        byte curveTypeId = bb.get();
        if (curveTypeId != 0x03) {
            throw new IllegalArgumentException("Unsupported curve type");
        }

        CurveType curveType = CurveType.NAMED;
        NamedCurve namedCurve = NamedCurve.findByValue(bb.getShort());

        if (namedCurve == null) {
            throw new IllegalArgumentException("Unsupported named curve");
        }

        byte pubkeyLength = bb.get();
        byte[] pubkey = new byte[pubkeyLength];
        bb.get(pubkey);

        SignatureScheme signatureScheme = SignatureScheme.findByValue(bb.getShort());

        if (signatureScheme == null) {
            throw new IllegalArgumentException("Unknown signature scheme");
        }

        short signatureLength = bb.getShort();
        byte[] signature = new byte[signatureLength];

        bb.get(signature);

        return new EcdheServerParams(curveType, namedCurve, pubkey, signatureScheme, signature);
    }

    // https://ldapwiki.com/wiki/ClientKeyExchange

    /**
     * Suitable for both DH and ECDHE
     *
     * @param rawData Handshake record content
     */
    public static byte[] getClientDHPubkey(byte[] rawData, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(rawData).position(offset);

        byte length = bb.get();
        byte[] pubkey = new byte[length];
        bb.get(pubkey);

        return pubkey;
    }

    public static byte[] getClientRsaPreMaster(byte[] rawData, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(rawData).position(offset);

        int length = bb.getShort();
        byte[] encryptedPreMaster = new byte[length];
        bb.get(encryptedPreMaster);

        return encryptedPreMaster;
    }

}
