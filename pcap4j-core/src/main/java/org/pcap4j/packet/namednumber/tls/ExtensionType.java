package org.pcap4j.packet.namednumber.tls;

import org.pcap4j.packet.namednumber.NamedNumber;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class ExtensionType extends NamedNumber<Short, ExtensionType> {

    private static final Map<Short, ExtensionType> registry = new HashMap<>();

    public static final ExtensionType SERVER_NAME = new ExtensionType((short) 0, "server_name");
    public static final ExtensionType MAX_FRAGMENT_LENGTH = new ExtensionType((short) 1, "max_fragment_length");
    public static final ExtensionType CLIENT_CERTIFICATE_URL = new ExtensionType((short) 2, "client_certificate_url");
    public static final ExtensionType TRUSTED_CA_KEYS = new ExtensionType((short) 3, "trusted_ca_keys");
    public static final ExtensionType TRUNCATED_HMAC = new ExtensionType((short) 4, "truncated_hmac");
    public static final ExtensionType STATUS_REQUEST = new ExtensionType((short) 5, "status_request");
    public static final ExtensionType USER_MAPPING = new ExtensionType((short) 6, "user_mapping");
    public static final ExtensionType CLIENT_AUTHZ = new ExtensionType((short) 7, "client_authz");
    public static final ExtensionType SERVER_AUTHZ = new ExtensionType((short) 8, "server_authz");
    public static final ExtensionType CERT_TYPE = new ExtensionType((short) 9, "cert_type");
    public static final ExtensionType SUPPORTED_GROUPS = new ExtensionType((short) 10, "supported_groups");
    public static final ExtensionType EC_POINT_FORMATS = new ExtensionType((short) 11, "ec_point_formats");
    public static final ExtensionType SRP = new ExtensionType((short) 12, "srp");
    public static final ExtensionType SIGNATURE_ALGORITHMS = new ExtensionType((short) 13, "signature_algorithms");
    public static final ExtensionType USE_SRTP = new ExtensionType((short) 14, "use_srtp");
    public static final ExtensionType HEARTBEAT = new ExtensionType((short) 15, "heartbeat");
    public static final ExtensionType APPLICATION_LAYER_PROTOCOL_NEGOTIATION = new ExtensionType((short) 16, "application_layer_protocol_negotiation");
    public static final ExtensionType STATUS_REQUEST_V2 = new ExtensionType((short) 17, "status_request_v2");
    public static final ExtensionType SIGNED_CERTIFICATE_TIMESTAMP = new ExtensionType((short) 18, "signed_certificate_timestamp");
    public static final ExtensionType CLIENT_CERTIFICATE_TYPE = new ExtensionType((short) 19, "client_certificate_type");
    public static final ExtensionType SERVER_CERTIFICATE_TYPE = new ExtensionType((short) 20, "server_certificate_type");
    public static final ExtensionType PADDING = new ExtensionType((short) 21, "padding");
    public static final ExtensionType ENCRYPT_THEN_MAC = new ExtensionType((short) 22, "encrypt_then_mac");
    public static final ExtensionType EXTENDED_MASTER_SECRET = new ExtensionType((short) 23, "extended_master_secret");
    public static final ExtensionType TOKEN_BINDING = new ExtensionType((short) 24, "token_binding");
    public static final ExtensionType CACHED_INFO = new ExtensionType((short) 25, "cached_info");
    public static final ExtensionType TLS_LTS = new ExtensionType((short) 26, "tls_lts");
    public static final ExtensionType COMPRESS_CERTIFICATE = new ExtensionType((short) 27, "compress_certificate");
    public static final ExtensionType RECORD_SIZE_LIMIT = new ExtensionType((short) 28, "record_size_limit");
    public static final ExtensionType PWD_PROTECT = new ExtensionType((short) 29, "pwd_protect");
    public static final ExtensionType PWD_CLEAR = new ExtensionType((short) 30, "pwd_clear");
    public static final ExtensionType PASSWORD_SALT = new ExtensionType((short) 31, "password_salt");
    public static final ExtensionType TICKET_PINNING = new ExtensionType((short) 32, "ticket_pinning");
    public static final ExtensionType TLS_CERT_WITH_EXTERN_PSK = new ExtensionType((short) 33, "tls_cert_with_extern_psk");
    public static final ExtensionType DELEGATED_CREDENTIALS = new ExtensionType((short) 34, "delegated_credentials");
    public static final ExtensionType SESSION_TICKET = new ExtensionType((short) 35, "session_ticket");
    public static final ExtensionType PRE_SHARED_KEY = new ExtensionType((short) 41, "pre_shared_key");
    public static final ExtensionType EARLY_DATA = new ExtensionType((short) 42, "early_data");
    public static final ExtensionType SUPPORTED_VERSIONS = new ExtensionType((short) 43, "supported_versions");
    public static final ExtensionType COOKIE = new ExtensionType((short) 44, "cookie");
    public static final ExtensionType PSK_KEY_EXCHANGE_MODES = new ExtensionType((short) 45, "psk_key_exchange_modes");
    public static final ExtensionType CERTIFICATE_AUTHORITIES = new ExtensionType((short) 47, "certificate_authorities");
    public static final ExtensionType OID_FILTERS = new ExtensionType((short) 48, "oid_filters");
    public static final ExtensionType POST_HANDSHAKE_AUTH = new ExtensionType((short) 49, "post_handshake_auth");
    public static final ExtensionType SIGNATURE_ALGORITHMS_CERT = new ExtensionType((short) 50, "signature_algorithms_cert");
    public static final ExtensionType KEY_SHARE = new ExtensionType((short) 51, "key_share");
    public static final ExtensionType TRANSPARENCY_INFO = new ExtensionType((short) 52, "transparency_info");
    public static final ExtensionType CONNECTION_ID = new ExtensionType((short) 53, "connection_id");
    public static final ExtensionType EXTERNAL_ID_HASH = new ExtensionType((short) 55, "external_id_hash");
    public static final ExtensionType EXTERNAL_SESSION_ID = new ExtensionType((short) 56, "external_session_id");
    public static final ExtensionType RESERVED_GREASE_2570 = new ExtensionType((short) 2570, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_6682 = new ExtensionType((short) 6682, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_10794 = new ExtensionType((short) 10794, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_14906 = new ExtensionType((short) 14906, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_19018 = new ExtensionType((short) 19018, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_23130 = new ExtensionType((short) 23130, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_27242 = new ExtensionType((short) 27242, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_31354 = new ExtensionType((short) 31354, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_35466 = new ExtensionType((short) 35466, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_39578 = new ExtensionType((short) 39578, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_43690 = new ExtensionType((short) 43690, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_47802 = new ExtensionType((short) 47802, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_51914 = new ExtensionType((short) 51914, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_56026 = new ExtensionType((short) 56026, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_60138 = new ExtensionType((short) 60138, "Reserved (GREASE)");
    public static final ExtensionType RESERVED_GREASE_64250 = new ExtensionType((short) 64250, "Reserved (GREASE)");
    public static final ExtensionType RENEGOTIATION_INFO = new ExtensionType((short) 65281, "renegotiation_info");

    public ExtensionType(Short value, String name) {
        super(value, name);
        registry.put(value, this);
    }

    public static ExtensionType getInstance(Short value) {
        if (registry.containsKey(value)) {
            return registry.get(value);
        } else {
            return new ExtensionType(value, "Unknown");
        }
    }

    @Override
    public int compareTo(ExtensionType o) {
        return value().compareTo(o.value());
    }
}
