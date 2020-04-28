package org.pcap4j.packet.namednumber.tls;

import org.pcap4j.packet.namednumber.NamedNumber;

import java.util.HashMap;
import java.util.Map;

public class AlertDescription extends NamedNumber<Byte, AlertDescription> {

    private static final Map<Byte, AlertDescription> registry = new HashMap<>();

    // https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132

    public static AlertDescription close_notify = new AlertDescription((byte) 0, "close_notify");
    public static AlertDescription unexpected_message = new AlertDescription((byte) 10, "unexpected_message");
    public static AlertDescription bad_record_mac = new AlertDescription((byte) 20, "bad_record_mac");
    public static AlertDescription decryption_failed_RESERVED = new AlertDescription((byte) 21, "decryption_failed_RESERVED");
    public static AlertDescription record_overflow = new AlertDescription((byte) 22, "record_overflow");
    public static AlertDescription decompression_failure_RESERVED = new AlertDescription((byte) 30, "decompression_failure_RESERVED");
    public static AlertDescription handshake_failure = new AlertDescription((byte) 40, "handshake_failure");
    public static AlertDescription no_certificate_RESERVED = new AlertDescription((byte) 41, "no_certificate_RESERVED");
    public static AlertDescription bad_certificate = new AlertDescription((byte) 42, "bad_certificate");
    public static AlertDescription unsupported_certificate = new AlertDescription((byte) 43, "unsupported_certificate");
    public static AlertDescription certificate_revoked = new AlertDescription((byte) 44, "certificate_revoked");
    public static AlertDescription certificate_expired = new AlertDescription((byte) 45, "certificate_expired");
    public static AlertDescription certificate_unknown = new AlertDescription((byte) 46, "certificate_unknown");
    public static AlertDescription illegal_parameter = new AlertDescription((byte) 47, "illegal_parameter");
    public static AlertDescription unknown_ca = new AlertDescription((byte) 48, "unknown_ca");
    public static AlertDescription access_denied = new AlertDescription((byte) 49, "access_denied");
    public static AlertDescription decode_error = new AlertDescription((byte) 50, "decode_error");
    public static AlertDescription decrypt_error = new AlertDescription((byte) 51, "decrypt_error");
    public static AlertDescription export_restriction_RESERVED = new AlertDescription((byte) 60, "export_restriction_RESERVED");
    public static AlertDescription protocol_version = new AlertDescription((byte) 70, "protocol_version");
    public static AlertDescription insufficient_security = new AlertDescription((byte) 71, "insufficient_security");
    public static AlertDescription internal_error = new AlertDescription((byte) 80, "internal_error");
    public static AlertDescription inappropriate_fallback = new AlertDescription((byte) 86, "inappropriate_fallback");
    public static AlertDescription user_canceled = new AlertDescription((byte) 90, "user_canceled");
    public static AlertDescription no_renegotiation_RESERVED = new AlertDescription((byte) 100, "no_renegotiation_RESERVED");
    public static AlertDescription missing_extension = new AlertDescription((byte) 109, "missing_extension");
    public static AlertDescription unsupported_extension = new AlertDescription((byte) 110, "unsupported_extension");
    public static AlertDescription certificate_unobtainable_RESERVED = new AlertDescription((byte) 111, "certificate_unobtainable_RESERVED");
    public static AlertDescription unrecognized_name = new AlertDescription((byte) 112, "unrecognized_name");
    public static AlertDescription bad_certificate_status_response = new AlertDescription((byte) 113, "bad_certificate_status_response");
    public static AlertDescription bad_certificate_hash_value_RESERVED = new AlertDescription((byte) 114, "bad_certificate_hash_value_RESERVED");
    public static AlertDescription unknown_psk_identity = new AlertDescription((byte) 115, "unknown_psk_identity");
    public static AlertDescription certificate_required = new AlertDescription((byte) 116, "certificate_required");
    public static AlertDescription no_application_protocol = new AlertDescription((byte) 120, "no_application_protocol");

    public AlertDescription(Byte value, String name) {
        super(value, name);
        registry.put(value, this);
    }

    public static AlertDescription getInstance(Byte value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            throw new IllegalArgumentException("Unknown alert description: " + value);
        }
    }

    @Override
    public int compareTo(AlertDescription o) {
        return value().compareTo(o.value());
    }

}
