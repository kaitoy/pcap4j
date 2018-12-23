/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public class PropertiesLoader {

  private static final Logger logger = LoggerFactory.getLogger(PropertiesLoader.class);

  private final String resourceName;
  private final boolean systemPropertiesOverPropertiesFile;
  private final boolean caching;
  private final Properties prop = new Properties();

  private final Map<String, Object> cache = new HashMap<String, Object>();

  /**
   * @param resourceName resourceName
   * @param systemPropertiesOverPropertiesFile systemPropertiesOverPropertiesFile
   * @param caching caching
   */
  public PropertiesLoader(
      String resourceName, boolean systemPropertiesOverPropertiesFile, boolean caching) {
    this.resourceName = resourceName;
    this.systemPropertiesOverPropertiesFile = systemPropertiesOverPropertiesFile;
    this.caching = caching;

    InputStream in = this.getClass().getClassLoader().getResourceAsStream(resourceName);
    if (in == null) {
      logger.warn("{} not found.", resourceName);
      return;
    }

    try {
      this.prop.load(in);
    } catch (IOException e) {
      logger.error("Exception follows", e);
    }
  }

  /** @return resource name */
  public final String getResourceName() {
    return resourceName;
  }

  /** @return a new Properties object containing properties loaded by this object. */
  public final Properties getProp() {
    Properties copy = new Properties();
    copy.putAll(prop);
    return copy;
  }

  /**
   * @return true if this object gives priority to the system properties over the properties loaded
   *     by this object; false otherwise.
   */
  public final boolean isSystemPropertiesOverPropertiesFile() {
    return systemPropertiesOverPropertiesFile;
  }

  /** @return true if this object is caching values of properties; false otherwise. */
  public final boolean isCaching() {
    return caching;
  }

  /**
   * @param key key
   * @param defaultValue defaultValue
   * @return a value got from a specified key.
   */
  public String getString(String key, String defaultValue) {
    synchronized (cache) {
      if (caching && cache.containsKey(key)) {
        String cacheValue = ((String) cache.get(key));
        logger.debug("[{}] Got {} from cache by {}", new Object[] {resourceName, cacheValue, key});
        return cacheValue;
      }

      String value = null;

      if (systemPropertiesOverPropertiesFile) {
        value = System.getProperty(key);
      }

      if (value != null) {
        logger.info("[System properties] Got {} by {}", value, key);
      } else {
        value = prop.getProperty(key);

        if (value != null) {
          logger.info("[{}] Got {} by {}", new Object[] {resourceName, value, key});
        } else {
          logger.info(
              "[{}] Could not get value by {}, use default value: {}",
              new Object[] {resourceName, key, defaultValue});
          value = defaultValue;
        }
      }

      if (caching) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   * @param key key
   * @param defaultValue defaultValue
   * @return an Integer object converted from a value got from a specified key.
   */
  public Integer getInteger(String key, Integer defaultValue) {
    synchronized (cache) {
      if (caching && cache.containsKey(key)) {
        Integer cacheValue = (Integer) cache.get(key);
        logger.debug("[{}] Got {} from cache by {}", new Object[] {resourceName, cacheValue, key});
        return cacheValue;
      }

      Integer value = null;

      if (systemPropertiesOverPropertiesFile) {
        value = Integer.getInteger(key);
      }

      if (value != null) {
        logger.info("[System properties] Got {} by {}", value, key);
      } else {
        String strValue = prop.getProperty(key);

        if (strValue != null) {
          try {
            value = Integer.decode(strValue);
            logger.info("[{}] Got {} by {}", new Object[] {resourceName, value, key});
          } catch (NumberFormatException e) {
            logger.warn(
                "[{}] {} is invalid for {}, use default value: {}",
                new Object[] {resourceName, strValue, key, defaultValue});
            value = defaultValue;
          }
        } else {
          logger.info(
              "[{}] Could not get value by {}, use default value: {}",
              new Object[] {resourceName, key, defaultValue});
          value = defaultValue;
        }
      }

      if (caching) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   * @param key key
   * @param defaultValue defaultValue
   * @return a Boolean object converted from a value got from a specified key.
   */
  public Boolean getBoolean(String key, Boolean defaultValue) {
    synchronized (cache) {
      if (caching && cache.containsKey(key)) {
        Boolean cacheValue = (Boolean) cache.get(key);
        logger.debug("[{}] Got {} from cache by {}", new Object[] {resourceName, cacheValue, key});
        return cacheValue;
      }

      Boolean value = null;

      if (systemPropertiesOverPropertiesFile) {
        String strValue = System.getProperty(key);

        if (strValue != null) {
          value = Boolean.valueOf(strValue);
          logger.info(
              "[System properties] Got \"{}\" which means {} by {}",
              new Object[] {strValue, value, key});
        }
      }

      if (value == null) {
        String strValue = prop.getProperty(key);

        if (strValue != null) {
          value = Boolean.valueOf(strValue);
          logger.info(
              "[{}] Got\"{}\" which means {} by {}",
              new Object[] {resourceName, strValue, value, key});
        } else {
          logger.info(
              "[{}] Could not get value by {}, use default value: {}",
              new Object[] {resourceName, key, defaultValue});
          value = defaultValue;
        }
      }

      if (caching) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   * @param <T> class
   * @param key key
   * @param defaultValue defaultValue
   * @return a Class object converted from a value got from a specified key.
   */
  public <T> Class<? extends T> getClass(String key, Class<? extends T> defaultValue) {
    synchronized (cache) {
      if (caching && cache.containsKey(key)) {
        @SuppressWarnings("unchecked")
        Class<? extends T> cacheValue = (Class<? extends T>) cache.get(key);
        logger.debug("[{}] Got {} from cache by {}", new Object[] {resourceName, cacheValue, key});
        return cacheValue;
      }

      Class<? extends T> value = null;

      if (systemPropertiesOverPropertiesFile) {
        String strValue = System.getProperty(key);

        if (strValue != null) {
          try {
            @SuppressWarnings("unchecked")
            Class<? extends T> clazz = (Class<? extends T>) Class.forName(strValue);
            value = clazz;

            logger.info("[System properties] Got {} by {}", strValue, key);
          } catch (ClassNotFoundException e) {
            logger.error(
                "[System properties] Got Invalid value: {} by {}, ignore it.", strValue, key);
          } catch (ClassCastException e) {
            logger.error(
                "[System properties] Got Invalid value: {} by {}, ignore it.", strValue, key);
          }
        }
      }

      if (value == null) {
        String strValue = prop.getProperty(key);

        if (strValue != null) {
          try {
            @SuppressWarnings("unchecked")
            Class<? extends T> clazz = (Class<? extends T>) Class.forName(strValue);
            value = clazz;
            logger.info("[{}] Got {} by {}", new Object[] {resourceName, strValue, key});
          } catch (ClassNotFoundException e) {
            logger.warn(
                "[{}] {} is invalid for {}, use default value: {}",
                new Object[] {resourceName, strValue, key, defaultValue});
            value = defaultValue;
          } catch (ClassCastException e) {
            logger.warn(
                "[{}] {} is invalid for {}, use default value: {}",
                new Object[] {resourceName, strValue, key, defaultValue});
            value = defaultValue;
          }
        } else {
          logger.info(
              "[{}] Could not get value by {}, use default value: {}",
              new Object[] {resourceName, key, defaultValue});
          value = defaultValue;
        }
      }

      if (caching) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   * @param key key
   * @param defaultValue defaultValue
   * @return an InetAddress object converted from a value got from a specified key.
   */
  public InetAddress getInetAddress(String key, InetAddress defaultValue) {
    synchronized (cache) {
      if (caching && cache.containsKey(key)) {
        InetAddress cacheValue = (InetAddress) cache.get(key);
        logger.debug("[{}] Got {} from cache by {}", new Object[] {resourceName, cacheValue, key});
        return cacheValue;
      }

      InetAddress value = null;

      if (systemPropertiesOverPropertiesFile) {
        String strValue = System.getProperty(key);

        if (strValue != null) {
          try {
            value = InetAddress.getByName(strValue);
            logger.info(
                "[System properties] Got \"{}\" which means {} by {}",
                new Object[] {strValue, value, key});
          } catch (UnknownHostException e) {
            logger.error(
                "[System properties] Got Invalid value: {} by {}, ignore it.", strValue, key);
          }
        }
      }

      if (value == null) {
        String strValue = prop.getProperty(key);

        if (strValue != null) {
          try {
            value = InetAddress.getByName(strValue);
            logger.info(
                "[{}] Got\"{}\" which means {} by {}",
                new Object[] {resourceName, strValue, value, key});
          } catch (UnknownHostException e) {
            logger.warn(
                "[{}] {} is invalid for {}, use default value: {}",
                new Object[] {resourceName, strValue, key, defaultValue});
            value = defaultValue;
          }
        } else {
          logger.info(
              "[{}] Could not get value by {}, use default value: {}",
              new Object[] {resourceName, key, defaultValue});
          value = defaultValue;
        }
      }

      if (caching) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   * @param key key
   * @param defaultValue defaultValue
   * @return an int array converted from a value got from a specified key.
   */
  public int[] getIntArray(String key, int[] defaultValue) {
    synchronized (cache) {
      if (caching && cache.containsKey(key)) {
        int[] cacheValue = (int[]) cache.get(key);
        logger.debug(
            "[{}] Got {} from cache by {}",
            new Object[] {resourceName, Arrays.toString(cacheValue), key});

        return cacheValue.clone();
      }

      int[] value = null;

      if (systemPropertiesOverPropertiesFile) {
        String csv = System.getProperty(key);

        if (csv != null) {
          try {
            String[] strInts = csv.split(",");
            value = new int[strInts.length];
            for (int i = 0; i < strInts.length; i++) {
              value[i] = Integer.parseInt(strInts[i]);
            }
            logger.info(
                "[System properties] Got \"{}\" which means {} by {}",
                new Object[] {csv, Arrays.toString(value), key});
          } catch (NumberFormatException e) {
            logger.error("[System properties] Got Invalid value: {} by {}, ignore it.", csv, key);
          }
        }
      }

      if (value == null) {
        String csv = prop.getProperty(key);

        if (csv != null) {
          try {
            String[] strInts = csv.split(",");
            value = new int[strInts.length];
            for (int i = 0; i < strInts.length; i++) {
              value[i] = Integer.parseInt(strInts[i]);
            }
            logger.info(
                "[{}] Got\"{}\" which means {} by {}",
                new Object[] {resourceName, csv, Arrays.toString(value), key});
          } catch (NumberFormatException e) {
            logger.warn(
                "[{}] {} is invalid for {}, use default value: {}",
                new Object[] {resourceName, csv, key, Arrays.toString(defaultValue)});
            value = defaultValue;
          }
        } else {
          logger.info(
              "[{}] Could not get value by {}, use default value: {}",
              new Object[] {resourceName, key, Arrays.toString(defaultValue)});
          value = defaultValue;
        }
      }

      if (caching) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /** */
  public final void clearCache() {
    synchronized (cache) {
      cache.clear();
    }
  }
}
