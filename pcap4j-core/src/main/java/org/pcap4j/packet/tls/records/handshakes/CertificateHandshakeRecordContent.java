package org.pcap4j.packet.tls.records.handshakes;

import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CertificateHandshakeRecordContent implements HandshakeRecordContent {

    /**
     * 0x0 - Certificates length
     * 0x3 - Certificate 1
     * <p>
     * Certificate:
     * 0x0    - Certificate length (cl)
     * 0x3    - Certificate data
     * 0x3+cl - Next certificate
     */

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

    @Override
    public byte[] toByteArray() {
        List<byte[]> list = new ArrayList<>();

        list.add(ByteArrays.threeBytesIntToByteArray(certificatesLength));
        for (byte[] cert : rawCertificates) {
            list.addAll(certificateToByteArray(cert));
        }

        return ByteArrays.concatenate(list);
    }

    private List<byte[]> certificateToByteArray(byte[] certificate) {
        return Arrays.asList(
                ByteArrays.threeBytesIntToByteArray(certificate.length),
                certificate
        );
    }
}
