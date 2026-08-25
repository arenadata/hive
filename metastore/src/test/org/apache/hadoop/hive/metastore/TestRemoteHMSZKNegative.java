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
package org.apache.hadoop.hive.metastore;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryOneTime;
import org.apache.curator.test.TestingServer;
import org.apache.hadoop.hive.common.ZooKeeperHiveHelper;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.conf.HiveConf.ConfVars;
import org.apache.zookeeper.CreateMode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestRemoteHMSZKNegative {
  private TestingServer zkServer;
  private CuratorFramework zkClient;
  private HiveConf conf;

  @Before
  public void setUp() throws Exception {
    String rootNamespace = getClass().getSimpleName();
    zkServer = new TestingServer();

    conf = new HiveConf(TestRemoteHMSZKNegative.class);
    conf.setVar(ConfVars.METASTOREURIS, zkServer.getConnectString());
    conf.setVar(ConfVars.METASTORE_ZOOKEEPER_NAMESPACE, rootNamespace);
    conf.setVar(ConfVars.METASTORE_SERVICE_DISCOVERY_MODE, "zookeeper");

    zkClient = CuratorFrameworkFactory.newClient(zkServer.getConnectString(),
        new RetryOneTime(2000));
    zkClient.start();
    zkClient.create()
        .creatingParentsIfNeeded()
        .withMode(CreateMode.PERSISTENT)
        .forPath(ZooKeeperHiveHelper.ZOOKEEPER_PATH_SEPARATOR + rootNamespace);
  }

  @After
  public void tearDown() throws Exception {
    if (zkClient != null) {
      zkClient.close();
      zkClient = null;
    }
    if (zkServer != null) {
      zkServer.close();
      zkServer = null;
    }
  }

  @Test
  public void testClientThrowsWhenNoMetaStoreRegisteredInZooKeeper() {
    try {
      new HiveMetaStoreClient(conf);
      fail("Expected MetaException");
    } catch (Exception e) {
      assertTrue(e instanceof MetaStoreServiceUnavailableException);
      assertTrue(e.getMessage().contains("No metastore service discovered in ZooKeeper"));
    }
  }
}
