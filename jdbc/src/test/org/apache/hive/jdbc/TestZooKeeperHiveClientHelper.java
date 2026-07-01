/*
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
package org.apache.hive.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.hive.jdbc.Utils.JdbcConnectionParams;
import org.junit.Test;

public class TestZooKeeperHiveClientHelper {

  @Test
  public void testSetZkSSLParamsReadsStoreTypes() {
    JdbcConnectionParams connParams = new JdbcConnectionParams();
    connParams.getSessionVars().put(JdbcConnectionParams.ZOOKEEPER_SSL_ENABLE, "true");
    connParams.getSessionVars().put(JdbcConnectionParams.ZOOKEEPER_KEYSTORE_LOCATION,
        "/tmp/client.p12");
    connParams.getSessionVars().put(JdbcConnectionParams.ZOOKEEPER_KEYSTORE_PASSWORD, "keypass");
    connParams.getSessionVars().put(JdbcConnectionParams.ZOOKEEPER_KEYSTORE_TYPE, "PKCS12");
    connParams.getSessionVars().put(JdbcConnectionParams.ZOOKEEPER_TRUSTSTORE_LOCATION,
        "/tmp/truststore.bcfks");
    connParams.getSessionVars().put(JdbcConnectionParams.ZOOKEEPER_TRUSTSTORE_PASSWORD,
        "trustpass");
    connParams.getSessionVars().put(JdbcConnectionParams.ZOOKEEPER_TRUSTSTORE_TYPE, "BCFKS");

    ZooKeeperHiveClientHelper.setZkSSLParams(connParams);

    assertTrue(connParams.isZooKeeperSslEnabled());
    assertEquals("/tmp/client.p12", connParams.getZookeeperKeyStoreLocation());
    assertEquals("keypass", connParams.getZookeeperKeyStorePassword());
    assertEquals("PKCS12", connParams.getZookeeperKeyStoreType());
    assertEquals("/tmp/truststore.bcfks", connParams.getZookeeperTrustStoreLocation());
    assertEquals("trustpass", connParams.getZookeeperTrustStorePassword());
    assertEquals("BCFKS", connParams.getZookeeperTrustStoreType());
  }
}
