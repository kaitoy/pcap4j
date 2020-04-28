package org.pcap4j.packet.tls.records.handshakes;

import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.List;

public class CertificateHandshakeRecordContent implements HandshakeRecordContent {

    private static final int CERTIFICATES_LENGTH_OFFSET = 0;
    private static final int CERTIFICATES_OFFSET = 3;

    private int certificatesLength;
    private List<byte[]> rawCertificates = new ArrayList<>();

    public static CertificateHandshakeRecordContent newInstance(byte[] rawData, int offset, int length) {
        return new CertificateHandshakeRecordContent(rawData, offset, length);
    }

    public CertificateHandshakeRecordContent(byte[] rawData, int offset, int length) {
        this.certificatesLength = ByteArrays.getThreeBytesInt(rawData, CERTIFICATES_LENGTH_OFFSET + offset);

        int cursor = CERTIFICATES_OFFSET + offset;
        while (cursor < offset + length) {
            int certificateLength = ByteArrays.getThreeBytesInt(rawData, cursor);
            cursor += 3;

            ByteArrays.validateBounds(rawData, cursor, certificateLength);
            byte[] certData = ByteArrays.getSubArray(rawData, cursor, certificateLength);
            rawCertificates.add(certData);
            cursor += certificateLength;
        }
    }

    public List<byte[]> getRawCertificates() {
        return rawCertificates;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("    Chain length: " + rawCertificates.size());

        for (byte[] cert : rawCertificates) {
            sb.append('\n');
            sb.append("    [").append(cert.length).append(" bytes]");
        }

        return sb.toString();
    }

}
