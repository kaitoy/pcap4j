package org.pcap4j.packet.namednumber.tls;

import org.pcap4j.packet.namednumber.NamedNumber;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class HandshakeType extends NamedNumber<Byte, HandshakeType> {

    private static final Map<Byte, HandshakeType> registry = new HashMap<>();

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

    public static final HandshakeType HELLO_REQUEST = new HandshakeType((byte) 0, "Hello Request");
    public static final HandshakeType CLIENT_HELLO = new HandshakeType((byte) 1, "Client Hello");
    public static final HandshakeType SERVER_HELLO = new HandshakeType((byte) 2, "Server Hello");
    public static final HandshakeType HELLO_VERIFY_REQUEST = new HandshakeType((byte) 3, "Hello Verify Request");
    public static final HandshakeType NEW_SESSION_TICKET = new HandshakeType((byte) 4, "New Session Ticket");
    public static final HandshakeType END_OF_EARLY_DATA = new HandshakeType((byte) 5, "End Of Early Data");
    public static final HandshakeType HELLO_RETRY_REQUEST = new HandshakeType((byte) 6, "Hello Retry Request");
    public static final HandshakeType ENCRYPTED_EXTENSIONS = new HandshakeType((byte) 8, "Encrypted Extensions");
    public static final HandshakeType CERTIFICATE = new HandshakeType((byte) 11, "Certificate");
    public static final HandshakeType SERVER_KEY_EXCHANGE = new HandshakeType((byte) 12, "Server Key Excange");
    public static final HandshakeType CERTIFICATE_REQUEST = new HandshakeType((byte) 13, "Certificate Request");
    public static final HandshakeType SERVER_HELLO_DONE = new HandshakeType((byte) 14, "Server Hello Done");
    public static final HandshakeType CERTIFICATE_VERIFY = new HandshakeType((byte) 15, "Certificate Verify");
    public static final HandshakeType CLIENT_KEY_EXCHANGE = new HandshakeType((byte) 16, "Client Key Exchange");
    public static final HandshakeType FINISHED = new HandshakeType((byte) 20, "Finished");
    public static final HandshakeType CERTIFICATE_URL = new HandshakeType((byte) 21, "Certificate URL");
    public static final HandshakeType CERTIFICATE_STATUS = new HandshakeType((byte) 22, "Certificate Status");
    public static final HandshakeType SUPPLEMENTAL_DATA = new HandshakeType((byte) 23, "Supplemental Data");
    public static final HandshakeType KEY_UPDATE = new HandshakeType((byte) 24, "Key Update");
    public static final HandshakeType COMPRESSED_CERTIFICATE = new HandshakeType((byte) 25, "Compressed Certificate");
    public static final HandshakeType MESSAGE_HASH = new HandshakeType((byte) 254, "Message Hash");

    public static final HandshakeType ENCRYPTED_HANDSHAKE_MESSAGE = new HandshakeType((byte) 255, "Encrypted Handshake Message");

    public HandshakeType(Byte value, String name) {
        super(value, name);
        registry.put(value, this);
    }

    public static HandshakeType getInstance(Byte value) {
        return registry.getOrDefault(value, ENCRYPTED_HANDSHAKE_MESSAGE);
    }

    @Override
    public int compareTo(HandshakeType o) {
        return value().compareTo(o.value());
    }
}
