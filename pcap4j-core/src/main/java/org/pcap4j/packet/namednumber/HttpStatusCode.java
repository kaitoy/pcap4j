/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class HttpStatusCode extends NamedNumber<Short, HttpStatusCode> {

  // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html

  /** */
  private static final long serialVersionUID = -7511956295870434744L;

  /** */
  public static final HttpStatusCode CONTINUE = new HttpStatusCode((short) 100, "Continue");

  /** */
  public static final HttpStatusCode SWITCHING_PROTOCOLS =
      new HttpStatusCode((short) 101, "Switching Protocols");

  /** */
  public static final HttpStatusCode OK = new HttpStatusCode((short) 200, "OK");

  /** */
  public static final HttpStatusCode CREATED = new HttpStatusCode((short) 201, "Created");

  /** */
  public static final HttpStatusCode ACCEPTED = new HttpStatusCode((short) 202, "Accepted");

  /** */
  public static final HttpStatusCode NON_AUTHORITATIVE_INFORMATION =
      new HttpStatusCode((short) 203, "Non-Authoritative Information");

  /** */
  public static final HttpStatusCode NO_CONTENT = new HttpStatusCode((short) 204, "No Content");

  /** */
  public static final HttpStatusCode RESET_CONTENT =
      new HttpStatusCode((short) 205, "Reset Content");

  /** */
  public static final HttpStatusCode PARTIAL_CONTENT =
      new HttpStatusCode((short) 206, "Partial Content");

  /** */
  public static final HttpStatusCode MULTIPLE_CHOICES =
      new HttpStatusCode((short) 300, "Multiple Choices");

  /** */
  public static final HttpStatusCode MOVED_PERMANENTLY =
      new HttpStatusCode((short) 301, "Moved Permanently");

  /** */
  public static final HttpStatusCode FOUND = new HttpStatusCode((short) 302, "Found");

  /** */
  public static final HttpStatusCode SEE_OTHER = new HttpStatusCode((short) 303, "See Other");

  /** */
  public static final HttpStatusCode NOT_MODIFIED = new HttpStatusCode((short) 304, "Not Modified");

  /** */
  public static final HttpStatusCode USE_PROXY = new HttpStatusCode((short) 305, "Use Proxy");

  /** */
  public static final HttpStatusCode TEMPORARY_REDIRECT =
      new HttpStatusCode((short) 307, "Temporary Redirect");

  /** */
  public static final HttpStatusCode BAD_REQUEST = new HttpStatusCode((short) 400, "Bad Request");

  /** */
  public static final HttpStatusCode UNAUTHORIZED = new HttpStatusCode((short) 401, "Unauthorized");

  /** */
  public static final HttpStatusCode PAYMENT_REQUIRED =
      new HttpStatusCode((short) 402, "Payment Required");

  /** */
  public static final HttpStatusCode FORBIDDEN = new HttpStatusCode((short) 403, "Forbidden");

  /** */
  public static final HttpStatusCode NOT_FOUND = new HttpStatusCode((short) 404, "Not Found");

  /** */
  public static final HttpStatusCode METHOD_NOT_ALLOWED =
      new HttpStatusCode((short) 405, "Method Not Allowed");

  /** */
  public static final HttpStatusCode NOT_ACCEPTABLE =
      new HttpStatusCode((short) 406, "Not Acceptable");

  /** */
  public static final HttpStatusCode PROXY_AUTHENTICATION_REQUIRED =
      new HttpStatusCode((short) 407, "Proxy Authentication Required");

  /** */
  public static final HttpStatusCode REQUEST_TIMEOUT =
      new HttpStatusCode((short) 408, "Request Time-out");

  /** */
  public static final HttpStatusCode CONFLICT = new HttpStatusCode((short) 409, "Conflict");

  /** */
  public static final HttpStatusCode Gone = new HttpStatusCode((short) 410, "Gone");

  /** */
  public static final HttpStatusCode LENGTH_REQUIRED =
      new HttpStatusCode((short) 411, "Length Required");

  /** */
  public static final HttpStatusCode PRECONDITION_FAILED =
      new HttpStatusCode((short) 412, "Precondition Failed");

  /** */
  public static final HttpStatusCode REQUEST_ENTITY_TOO_LARGE =
      new HttpStatusCode((short) 413, "Request Entity Too Large");

  /** */
  public static final HttpStatusCode REQUEST_URI_TOO_LARGE =
      new HttpStatusCode((short) 414, "Request-URI Too Large");

  /** */
  public static final HttpStatusCode UNSUPPORTED_MEDIA_TYPE =
      new HttpStatusCode((short) 415, "Unsupported Media Type");

  /** */
  public static final HttpStatusCode REQUESTED_RANGE_NOT_SATISFIABLE =
      new HttpStatusCode((short) 416, "Requested range not satisfiable");

  /** */
  public static final HttpStatusCode EXPECTATION_FAILED =
      new HttpStatusCode((short) 417, "Expectation Failed");

  /** */
  public static final HttpStatusCode INTERNAL_SERVER_ERROR =
      new HttpStatusCode((short) 500, "Internal Server Error");

  /** */
  public static final HttpStatusCode NOT_IMPLEMENTED =
      new HttpStatusCode((short) 501, "Not Implemented");

  /** */
  public static final HttpStatusCode BAD_GATEWAY = new HttpStatusCode((short) 502, "Bad Gateway");

  /** */
  public static final HttpStatusCode SERVICE_UNAVAILABLE =
      new HttpStatusCode((short) 503, "Service Unavailable");

  /** */
  public static final HttpStatusCode GATEWAY_TIMEOUT =
      new HttpStatusCode((short) 504, "Gateway Time-out");

  /** */
  public static final HttpStatusCode HTTP_VERSION_NOT_SUPPORTED =
      new HttpStatusCode((short) 505, "HTTP Version not supported");

  private static final Map<Short, HttpStatusCode> registry = new HashMap<Short, HttpStatusCode>();

  static {
    for (Field field : HttpStatusCode.class.getFields()) {
      if (HttpStatusCode.class.isAssignableFrom(field.getType())) {
        try {
          HttpStatusCode f = (HttpStatusCode) field.get(null);
          registry.put(f.value(), f);
        } catch (IllegalArgumentException e) {
          throw new AssertionError(e);
        } catch (IllegalAccessException e) {
          throw new AssertionError(e);
        } catch (NullPointerException e) {
          continue;
        }
      }
    }
  }

  private final HttpStatusClass statusClass;

  /**
   * @param value value
   * @param name name
   */
  public HttpStatusCode(Short value, String name) {
    super(value, name);
    if (value < 100 || value > 999) {
      throw new IllegalArgumentException(
          "The value must be between 100 and 999 inclusive but: " + value);
    }

    if (value < 200) {
      this.statusClass = HttpStatusClass.INFORMATIONAL;
    } else if (value < 300) {
      this.statusClass = HttpStatusClass.SUCCESS;
    } else if (value < 400) {
      this.statusClass = HttpStatusClass.REDIRECTION;
    } else if (value < 500) {
      this.statusClass = HttpStatusClass.CLIENT_ERROR;
    } else if (value < 600) {
      this.statusClass = HttpStatusClass.SERVER_ERROR;
    } else {
      this.statusClass = HttpStatusClass.EXTENSION;
    }
  }

  /** @return statusClass */
  public HttpStatusClass getStatusClass() {
    return statusClass;
  }

  /**
   * @param value value
   * @return a HttpStatusCode object.
   */
  public static HttpStatusCode getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new HttpStatusCode(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a HttpStatusCode object.
   */
  public static HttpStatusCode register(HttpStatusCode number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(HttpStatusCode o) {
    return value().compareTo(o.value());
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.2.1
   */
  public static enum HttpStatusClass {

    /** */
    INFORMATIONAL,

    /** */
    SUCCESS,

    /** */
    REDIRECTION,

    /** */
    CLIENT_ERROR,

    /** */
    SERVER_ERROR,

    /** */
    EXTENSION
  }
}
