/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
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

public class PropertiesLoader {

  protected static final Logger logger
    = Logger.getLogger(PropertiesLoader.class);

  private final String resourceName;
  private final Properties prop = new Properties();

  private boolean gettingPropertiesFromSystemBeforeFile = true;
  private boolean usingCache = true;
  private Map<String, Object> cache = new HashMap<String, Object>();

  public PropertiesLoader(String resourceName) {
    this.resourceName = resourceName;

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

  public final String getResourceName() {
    return resourceName;
  }

  public final Properties getProp() {
    Properties copy = new Properties();
    copy.putAll(prop);
    return copy;
  }

  public final void setGettingPropertiesFromSystemBeforeFile(
    boolean gettingPropertiesFromSystemBeforeFile
  ) {
    this.gettingPropertiesFromSystemBeforeFile
      = gettingPropertiesFromSystemBeforeFile;
  }

  public final boolean isGettingPropertiesFromSystemBeforeFile() {
    return gettingPropertiesFromSystemBeforeFile;
  }

  public final void setUsingCache(boolean usingCache) {
    if (!usingCache) {
      clearCache();
    }
    this.usingCache = usingCache;
  }

  public final boolean isUsingCache() {
    return usingCache;
  }

  public String getString(String key, String defaultValue) {
    StringBuilder sb = new StringBuilder();

    if (usingCache && cache.containsKey(key)) {
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

    if (gettingPropertiesFromSystemBeforeFile) {
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
    if (usingCache) {
      cache.put(key, value);
    }

    return value;
  }

  public int getInteger(String key, Integer defaultValue) {
    StringBuilder sb = new StringBuilder();

    if (usingCache && cache.containsKey(key)) {
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

    if (gettingPropertiesFromSystemBeforeFile) {
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

    if (usingCache) {
      cache.put(key, value);
    }

    return value;
  }

  public Boolean getBoolean(String key, Boolean defaultValue) {
    StringBuilder sb = new StringBuilder();

    if (usingCache && cache.containsKey(key)) {
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

    if (gettingPropertiesFromSystemBeforeFile) {
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

    if (usingCache) {
      cache.put(key, value);
    }

    return value;
  }

  public <T> Class<? extends T> getClass(String key, Class<? extends T> defaultValue) {
    StringBuilder sb = new StringBuilder();

    if (usingCache && cache.containsKey(key)) {
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

    if (gettingPropertiesFromSystemBeforeFile) {
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

    if (usingCache) {
      cache.put(key, value);
    }

    return value;
  }

  public final void clearCache() {
    cache.clear();
  }

}
