package org.pcap4j.util;

import org.pcap4j.packet.tls.keys.enums.SignatureScheme;

public class DhClientParams {

    private final byte[] p;
    private final byte[] g;
    private final byte[] pubkey;
    private final SignatureScheme signatureScheme;
    private final byte[] signature;

    public DhClientParams(byte[] p, byte[] g, byte[] pubkey,
                          SignatureScheme signatureScheme,
                          byte[] signature) {
        this.p = p;
        this.g = g;
        this.pubkey = pubkey;
        this.signatureScheme = signatureScheme;
        this.signature = signature;
    }

    public byte[] getP() {
        return p;
    }

    public byte[] getG() {
        return g;
    }

    public byte[] getPubkey() {
        return pubkey;
    }

    public SignatureScheme getSignatureScheme() {
        return signatureScheme;
    }

    public byte[] getSignature() {
        return signature;
    }
}
