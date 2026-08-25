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

import java.lang.reflect.Field;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.curator.test.TestingServer;
import org.apache.hadoop.hive.common.ZooKeeperHiveHelper;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.conf.HiveConf.ConfVars;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.NoSuchObjectException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TestRemoteHiveMetaStoreZK {
  private static TestingServer zkServer;
  private static HiveConf hiveConf;
  private static HiveMetaStoreClient client;

  @BeforeClass
  public static void startMetaStoreServer() throws Exception {
    zkServer = new TestingServer();

    HiveConf metastoreConf = new HiveConf(TestRemoteHiveMetaStoreZK.class);
    configureMetaStore(metastoreConf);
    configureZooKeeperServiceDiscovery(metastoreConf);
    MetaStoreUtils.startMetaStoreWithRetry(metastoreConf);
    waitForMetaStoreRegistration(metastoreConf);

    hiveConf = new HiveConf(TestRemoteHiveMetaStoreZK.class);
    configureMetaStore(hiveConf);
    configureZooKeeperServiceDiscovery(hiveConf);
  }

  @AfterClass
  public static void stopZooKeeperServer() throws Exception {
    if (zkServer != null) {
      zkServer.close();
      zkServer = null;
    }
  }

  @Before
  public void createClient() throws Exception {
    client = new HiveMetaStoreClient(hiveConf);
  }

  @After
  public void closeClient() {
    if (client != null) {
      client.close();
      client = null;
    }
  }

  @Test
  public void testClientConnectsThroughZooKeeper() throws Exception {
    String dbName = "test_remote_hms_zk";
    Database db = new Database();
    db.setName(dbName);

    dropDatabaseIfExists(dbName);
    client.createDatabase(db);

    try {
      assertEquals(dbName, client.getDatabase(dbName).getName());
    } finally {
      client.dropDatabase(dbName, true, true, true);
    }
  }

  @Test
  public void testClientConnectsAfterMetaStoreRegistersAgain() throws Exception {
    closeClient();
    removeMetaStoreRegistration();
    waitForNoMetaStoreRegistration(hiveConf);

    HiveConf restartedMetaStoreConf = new HiveConf(TestRemoteHiveMetaStoreZK.class);
    configureMetaStore(restartedMetaStoreConf);
    configureZooKeeperServiceDiscovery(restartedMetaStoreConf);
    MetaStoreUtils.startMetaStoreWithRetry(restartedMetaStoreConf);
    waitForMetaStoreRegistration(restartedMetaStoreConf);

    client = new HiveMetaStoreClient(hiveConf);
    assertEquals("default", client.getDatabase("default").getName());
  }

  @Test
  public void testClientConnectsAfterZooKeeperRestart() throws Exception {
    closeClient();

    zkServer.stop();
    zkServer.restart();
    waitForMetaStoreRegistration(hiveConf);

    client = new HiveMetaStoreClient(hiveConf);
    assertEquals("default", client.getDatabase("default").getName());
  }

  @Test
  public void testRetryingClientWaitsForMetaStoreToRegisterAgain() throws Exception {
    closeClient();

    HiveConf retryingClientConf = new HiveConf(hiveConf);
    retryingClientConf.setIntVar(ConfVars.METASTORETHRIFTFAILURERETRIES, 30);
    retryingClientConf.setTimeVar(ConfVars.METASTORE_CLIENT_CONNECT_RETRY_DELAY, 1,
        TimeUnit.SECONDS);
    retryingClientConf.setTimeVar(ConfVars.METASTORE_CLIENT_SOCKET_LIFETIME, 1,
        TimeUnit.MILLISECONDS);
    final IMetaStoreClient retryingClient = RetryingMetaStoreClient.getProxy(
        retryingClientConf, null, HiveMetaStoreClient.class.getName());

    removeMetaStoreRegistration();
    waitForNoMetaStoreRegistration(hiveConf);

    final AtomicReference<Throwable> registrationFailure = new AtomicReference<>();
    Thread registrationThread = new Thread(new Runnable() {
      @Override
      public void run() {
        try {
          Thread.sleep(250);
          HiveConf restartedMetaStoreConf = new HiveConf(TestRemoteHiveMetaStoreZK.class);
          configureMetaStore(restartedMetaStoreConf);
          configureZooKeeperServiceDiscovery(restartedMetaStoreConf);
          MetaStoreUtils.startMetaStoreWithRetry(restartedMetaStoreConf);
          waitForMetaStoreRegistration(restartedMetaStoreConf);
        } catch (Throwable t) {
          registrationFailure.set(t);
        }
      }
    }, "metastore-zookeeper-registration");
    registrationThread.start();

    try {
      assertEquals("default", retryingClient.getDatabase("default").getName());
    } finally {
      retryingClient.close();
      registrationThread.join(TimeUnit.SECONDS.toMillis(30));
    }

    if (registrationThread.isAlive()) {
      registrationThread.interrupt();
      throw new AssertionError("Timed out waiting for the Metastore to register in ZooKeeper");
    }
    if (registrationFailure.get() != null) {
      AssertionError error = new AssertionError("Unable to register the Metastore in ZooKeeper");
      error.initCause(registrationFailure.get());
      throw error;
    }
  }

  protected static void configureZooKeeperServiceDiscovery(HiveConf conf) {
    conf.setVar(ConfVars.METASTOREURIS, zkServer.getConnectString());
    conf.setVar(ConfVars.METASTORE_ZOOKEEPER_NAMESPACE,
        TestRemoteHiveMetaStoreZK.class.getSimpleName());
    conf.setVar(ConfVars.METASTORE_SERVICE_DISCOVERY_MODE, "zookeeper");
  }

  private static void configureMetaStore(HiveConf conf) {
    conf.setClass(ConfVars.METASTORE_EXPRESSION_PROXY_CLASS.varname,
        MockPartitionExpressionForMetastore.class, PartitionExpressionProxy.class);
    conf.setIntVar(ConfVars.METASTORETHRIFTCONNECTIONRETRIES, 3);
    conf.setTimeVar(ConfVars.METASTORE_CLIENT_CONNECT_RETRY_DELAY, 100,
        TimeUnit.MILLISECONDS);
    conf.setTimeVar(ConfVars.METASTORE_CLIENT_CONNECTION_TIMEOUT, 5,
        TimeUnit.SECONDS);
    conf.setTimeVar(ConfVars.METASTORE_CLIENT_SOCKET_TIMEOUT, 30,
        TimeUnit.SECONDS);
  }

  private static void waitForMetaStoreRegistration(HiveConf conf) throws Exception {
    long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30);
    Exception lastException = null;
    while (System.currentTimeMillis() < deadline) {
      try {
        List<String> serverUris = conf.getMetastoreZKConfig().getServerUris();
        if (!serverUris.isEmpty()) {
          return;
        }
      } catch (Exception e) {
        lastException = e;
      }
      Thread.sleep(250);
    }

    AssertionError error = new AssertionError("No metastore instance registered in ZooKeeper "
        + "namespace " + conf.getVar(ConfVars.METASTORE_ZOOKEEPER_NAMESPACE));
    if (lastException != null) {
      error.initCause(lastException);
    }
    throw error;
  }

  private static void waitForNoMetaStoreRegistration(HiveConf conf) throws Exception {
    long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30);
    List<String> serverUris = null;
    while (System.currentTimeMillis() < deadline) {
      serverUris = conf.getMetastoreZKConfig().getServerUris();
      if (serverUris.isEmpty()) {
        return;
      }
      Thread.sleep(250);
    }

    throw new AssertionError("Metastore instances are still registered in ZooKeeper namespace "
        + conf.getVar(ConfVars.METASTORE_ZOOKEEPER_NAMESPACE) + ": " + serverUris);
  }

  private static void removeMetaStoreRegistration() throws Exception {
    ZooKeeperHiveHelper zooKeeperHiveHelper = getMetaStoreZooKeeperHelper();
    zooKeeperHiveHelper.removeServerInstanceFromZooKeeper();
  }

  private static ZooKeeperHiveHelper getMetaStoreZooKeeperHelper() throws Exception {
    Field field = HiveMetaStore.class.getDeclaredField("zooKeeperHelper");
    field.setAccessible(true);
    return (ZooKeeperHiveHelper) field.get(null);
  }

  private static void dropDatabaseIfExists(String dbName) throws Exception {
    try {
      client.dropDatabase(dbName, true, true, true);
    } catch (NoSuchObjectException e) {
      // Ignore missing databases left from previous cleanup attempts.
    }
  }
}
