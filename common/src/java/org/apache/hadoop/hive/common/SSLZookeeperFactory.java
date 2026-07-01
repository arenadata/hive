/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hive.common;

import java.security.KeyStore;

import org.apache.commons.lang3.StringUtils;
import org.apache.curator.utils.ZookeeperFactory;
import org.apache.zookeeper.ClientCnxnSocketNetty;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.client.ZKClientConfig;
import org.apache.zookeeper.common.ClientX509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory to create ZooKeeper clients with TLS enabled.
 */
public class SSLZookeeperFactory implements ZookeeperFactory {
  private static final Logger LOG = LoggerFactory.getLogger(SSLZookeeperFactory.class);

  private final boolean sslEnabled;
  private final String keyStoreLocation;
  private final String keyStorePassword;
  private final String keyStoreType;
  private final String trustStoreLocation;
  private final String trustStorePassword;
  private final String trustStoreType;

  public SSLZookeeperFactory(boolean sslEnabled, String keyStoreLocation, String keyStorePassword,
      String keyStoreType, String trustStoreLocation, String trustStorePassword,
      String trustStoreType) {
    this.sslEnabled = sslEnabled;
    this.keyStoreLocation = StringUtils.defaultString(keyStoreLocation, "");
    this.keyStorePassword = StringUtils.defaultString(keyStorePassword, "");
    this.keyStoreType = StringUtils.isBlank(keyStoreType) ? KeyStore.getDefaultType() : keyStoreType;
    this.trustStoreLocation = StringUtils.defaultString(trustStoreLocation, "");
    this.trustStorePassword = StringUtils.defaultString(trustStorePassword, "");
    this.trustStoreType = StringUtils.isBlank(trustStoreType) ? KeyStore.getDefaultType() : trustStoreType;
    if (sslEnabled) {
      if (StringUtils.isBlank(keyStoreLocation)) {
        LOG.warn("Missing ZooKeeper keystore location");
      }
      if (StringUtils.isBlank(trustStoreLocation)) {
        LOG.warn("Missing ZooKeeper truststore location");
      }
    }
  }

  @Override
  public ZooKeeper newZooKeeper(String connectString, int sessionTimeout, Watcher watcher,
      boolean canBeReadOnly) throws Exception {
    if (!sslEnabled) {
      return new ZooKeeper(connectString, sessionTimeout, watcher, canBeReadOnly);
    }

    ZKClientConfig clientConfig = new ZKClientConfig();
    clientConfig.setProperty(ZKClientConfig.SECURE_CLIENT, "true");
    clientConfig.setProperty(ZKClientConfig.ZOOKEEPER_CLIENT_CNXN_SOCKET,
        ClientCnxnSocketNetty.class.getName());

    ClientX509Util x509Util = new ClientX509Util();
    clientConfig.setProperty(x509Util.getSslKeystoreLocationProperty(), keyStoreLocation);
    clientConfig.setProperty(x509Util.getSslKeystorePasswdProperty(), keyStorePassword);
    clientConfig.setProperty(x509Util.getSslKeystoreTypeProperty(), keyStoreType);
    clientConfig.setProperty(x509Util.getSslTruststoreLocationProperty(), trustStoreLocation);
    clientConfig.setProperty(x509Util.getSslTruststorePasswdProperty(), trustStorePassword);
    clientConfig.setProperty(x509Util.getSslTruststoreTypeProperty(), trustStoreType);

    return new ZooKeeper(connectString, sessionTimeout, watcher, canBeReadOnly, clientConfig);
  }
}
