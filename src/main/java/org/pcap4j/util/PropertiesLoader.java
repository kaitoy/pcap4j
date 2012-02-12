/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public class PropertiesLoader {

  private static final Logger logger
    = Logger.getLogger(PropertiesLoader.class.getPackage().getName());

  private final String resourceName;
  private final boolean givePrioritySystemPropertiesThanPropertiesFile;
  private final boolean useCache;
  private final Properties prop = new Properties();

  private final Map<String, Object> cache = new HashMap<String, Object>();

  /**
   *
   * @param resourceName
   */
  public PropertiesLoader(
    String resourceName,
    boolean givePrioritySystemPropertiesThanPropertiesFile,
    boolean useCache
  ) {
    this.resourceName = resourceName;
    this.givePrioritySystemPropertiesThanPropertiesFile
      = givePrioritySystemPropertiesThanPropertiesFile;
    this.useCache = useCache;

    InputStream in
      = this.getClass().getClassLoader().getResourceAsStream(resourceName);
    if (in == null) {
      logger.warn(resourceName + " not found.");
      return;
    }

    try {
      this.prop.load(
        this.getClass().getClassLoader().getResourceAsStream(resourceName)
      );
    } catch (IOException e) {
      logger.error(e);
    }
  }

  /**
   *
   * @return
   */
  public final String getResourceName() {
    return resourceName;
  }

  /**
   *
   * @return
   */
  public final Properties getProp() {
    Properties copy = new Properties();
    copy.putAll(prop);
    return copy;
  }

  /**
   *
   * @return
   */
  public final boolean isGivingPrioritySystemPropertiesThanPropertiesFile() {
    return givePrioritySystemPropertiesThanPropertiesFile;
  }

  /**
   *
   * @return
   */
  public final boolean isUsingCache() {
    return useCache;
  }

  /**
   *
   * @param key
   * @param defaultValue
   * @return
   */
  public String getString(String key, String defaultValue) {
    StringBuilder sb = new StringBuilder();

    synchronized (cache) {
      if (useCache && cache.containsKey(key)) {
        String cacheValue = ((String)cache.get(key));
        if (logger.isDebugEnabled()) {
          logger.debug(
            sb.append("[").append(resourceName).append("] Got ")
              .append(cacheValue).append(" from cache for ").append(key)
          );
        }
        return cacheValue;
      }

      String value = null;

      if (givePrioritySystemPropertiesThanPropertiesFile) {
        value = System.getProperty(key);
      }

      if (value != null) {
        logger.info(
          sb.append("[System properties] Got ")
            .append(value).append(" for ").append(key)
        );
      }
      else {
        value = prop.getProperty(key);

        if (value != null) {
          logger.info(
            sb.append("[").append(resourceName).append("] Got ")
              .append(value).append(" for ").append(key)
          );
        }
        else {
          logger.warn(
            sb.append("[").append(resourceName)
              .append("] Could not get value for ").append(key)
              .append(", use defalut value: ").append(defaultValue)

          );
          value = defaultValue;
        }
      }

      if (useCache) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   *
   * @param key
   * @param defaultValue
   * @return
   */
  public int getInteger(String key, Integer defaultValue) {
    StringBuilder sb = new StringBuilder();

    synchronized (cache) {
      if (useCache && cache.containsKey(key)) {
        Integer cacheValue = (Integer)cache.get(key);
        if (logger.isDebugEnabled()) {
          logger.debug(
            sb.append("[").append(resourceName).append("] Got ")
              .append(cacheValue).append(" from cache for ").append(key)
          );
        }
        return cacheValue;
      }

      Integer value = null;

      if (givePrioritySystemPropertiesThanPropertiesFile) {
        value = Integer.getInteger(key);
      }

      if (value != null) {
        logger.info(
          sb.append("[System properties] Got ")
            .append(value).append(" for ").append(key)
        );
      }
      else {
        String strValue = prop.getProperty(key);

        if (strValue != null) {
          try {
            value = Integer.decode(strValue);
            logger.info(
              sb.append("[").append(resourceName).append("] Got ")
                .append(value).append(" for ").append(key)
            );
          } catch (NumberFormatException e) {
            logger.warn(
              sb.append("[").append(resourceName).append("] ")
                .append(strValue).append(" is invalid for ").append(key)
                .append(", use defalut value: ").append(defaultValue)
            );
            value = defaultValue;
          }
        }
        else {
          logger.warn(
            sb.append("[").append(resourceName)
              .append("] Could not get value for ").append(key)
              .append(", use defalut value: ").append(defaultValue)
          );
          value = defaultValue;
        }
      }

      if (useCache) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   *
   * @param key
   * @param defaultValue
   * @return
   */
  public Boolean getBoolean(String key, Boolean defaultValue) {
    StringBuilder sb = new StringBuilder();

    synchronized (cache) {
      if (useCache && cache.containsKey(key)) {
        Boolean cacheValue = (Boolean)cache.get(key);
        if (logger.isDebugEnabled()) {
          logger.debug(
            sb.append("[").append(resourceName).append("] Got ")
              .append(cacheValue).append(" from cache for ").append(key)
          );
        }
        return cacheValue;
      }

      Boolean value = null;

      if (givePrioritySystemPropertiesThanPropertiesFile) {
        String strValue = System.getProperty(key);

        if (strValue != null) {
          value = Boolean.valueOf(strValue);
          logger.info(
            sb.append("[System properties] Got \"")
              .append(strValue).append("\" means ").append(value)
              .append(" for ").append(key)
          );
        }
      }

      if (value == null) {
        String strValue = prop.getProperty(key);

        if (strValue != null) {
          value = Boolean.valueOf(strValue);
          logger.info(
            sb.append("[").append(resourceName).append("] Got \"")
              .append(strValue).append("\" means ").append(value)
              .append(" for ").append(key)

          );
        }
        else {
          logger.warn(
            sb.append("[").append(resourceName)
              .append("] Could not get value for ").append(key)
              .append(", use defalut value: ").append(defaultValue)
          );
          value = defaultValue;
        }
      }

      if (useCache) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   *
   * @param key
   * @param defaultValue
   * @return
   */
  public <T> Class<? extends T> getClass(String key, Class<? extends T> defaultValue) {
    StringBuilder sb = new StringBuilder();

    synchronized (cache) {
      if (useCache && cache.containsKey(key)) {
        @SuppressWarnings("unchecked")
        Class<? extends T> cacheValue = (Class<? extends T>)cache.get(key);
        if (logger.isDebugEnabled()) {
          logger.debug(
            sb.append("[").append(resourceName).append("] Got ")
              .append(cacheValue).append(" from cache for ").append(key)
          );
        }
        return cacheValue;
      }

      Class<? extends T> value = null;

      if (givePrioritySystemPropertiesThanPropertiesFile) {
        String strValue = System.getProperty(key);

        if (strValue != null) {
          try {
            @SuppressWarnings("unchecked")
            Class<? extends T> clazz
              = (Class<? extends T>)Class.forName(strValue);
            value = clazz;
            logger.info(
              sb.append("[System properties] Got ")
                .append(strValue).append(" for ").append(key)
            );
          } catch (ClassNotFoundException e) {
            logger.error(
              sb.append("[System properties] Got Invalid value: ")
                .append(strValue).append(" for ").append(key)
                .append(", ignore it.")
            );
          } catch (ClassCastException e) {
            logger.error(
              sb.append("[System properties] Got Invalid value: ")
                .append(strValue).append(" for ").append(key)
                .append(", ignore it.")
            );
          }
        }
      }

      if (value == null) {
        String strValue = prop.getProperty(key);

        if (strValue != null) {
          try {
            @SuppressWarnings("unchecked")
            Class<? extends T> clazz
              = (Class<? extends T>)Class.forName(strValue);
            value = clazz;
            logger.info(
              sb.append("[").append(resourceName).append("] Got ")
                .append(strValue).append(" for ").append(key)
            );
          } catch (ClassNotFoundException e) {
            logger.warn(
              sb.append("[").append(resourceName).append("] ")
                .append(strValue).append(" is invalid for ").append(key)
                .append(", use defalut value: ").append(defaultValue)
            );
            value = defaultValue;
          } catch (ClassCastException e) {
            logger.warn(
              sb.append("[").append(resourceName).append("] ")
                .append(strValue).append(" is invalid for ").append(key)
                .append(", use defalut value: ").append(defaultValue)
            );
            value = defaultValue;
          }
        }
        else {
          logger.warn(
            sb.append("[").append(resourceName)
              .append("] Could not get value for ").append(key)
              .append(", use defalut value: ").append(defaultValue)
          );
          value = defaultValue;
        }
      }

      if (useCache) {
        cache.put(key, value);
      }

      return value;
    }
  }

  /**
   *
   */
  public final void clearCache() {
    synchronized (cache) {
      cache.clear();
    }
  }

}
