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

package org.apache.hadoop.hive.metastore;

import java.util.HashMap;
import java.util.Map;

import io.fabric8.kubernetes.api.model.ServiceBuilder;
import io.fabric8.kubernetes.api.model.ServicePortBuilder;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointBuilder;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointPortBuilder;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointSliceBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMixedDispatcher;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import io.fabric8.mockwebserver.Context;
import io.fabric8.mockwebserver.MockWebServer;
import org.apache.hadoop.hive.common.KubernetesHiveHelper;
import org.apache.hadoop.hive.metastore.annotation.MetastoreCheckinTest;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf.ConfVars;
import org.junit.Before;
import org.junit.experimental.categories.Category;

@Category(MetastoreCheckinTest.class)
public class TestRemoteHiveMetaStoreKubernetes extends TestRemoteHiveMetaStore {
  private static final String NAMESPACE = "hms";
  private static final String SERVICE_NAME = "hive-metastore";
  private static KubernetesMockServer k8sServer = null;
  private static KubernetesClient k8sClient = null;

  @Before
  public void setUp() throws Exception {
    // Start the mock Kubernetes API server if not done already. The metastore server
    // registers nowhere in kubernetes mode: the Service and its EndpointSlice, maintained
    // by Kubernetes itself in a real deployment, stand in for the registration.
    if (k8sServer == null) {
      k8sServer = new KubernetesMockServer(new Context(), new MockWebServer(), new HashMap<>(),
          new KubernetesMixedDispatcher(new HashMap<>()), false);
      k8sServer.init();
      k8sClient = k8sServer.createClient();
      initConf();
      MetastoreConf.setVar(conf, ConfVars.THRIFT_SERVICE_DISCOVERY_MODE, "k8s");
      MetastoreConf.setVar(conf, ConfVars.KUBERNETES_NAMESPACES, NAMESPACE);
      MetastoreConf.setVar(conf, ConfVars.KUBERNETES_MASTER_URL,
          k8sClient.getConfiguration().getMasterUrl());
    }
    super.setUp();
  }

  @Override
  protected HiveMetaStoreClient createClient() throws Exception {
    k8sClient.services().inNamespace(NAMESPACE).resource(new ServiceBuilder()
        .withNewMetadata()
        .withName(SERVICE_NAME)
        .withNamespace(NAMESPACE)
        .withLabels(Map.of(KubernetesHiveHelper.DISCOVERY_LABEL, KubernetesHiveHelper.DISCOVERY_TYPE))
        .endMetadata()
        .withNewSpec()
        .withPorts(new ServicePortBuilder().withName("thrift").withPort(port).build())
        .endSpec()
        .build()).createOrReplace();
    k8sClient.discovery().v1().endpointSlices().inNamespace(NAMESPACE)
        .resource(new EndpointSliceBuilder()
            .withNewMetadata()
            .withName(SERVICE_NAME + "-xyz")
            .withNamespace(NAMESPACE)
            .withLabels(Map.of("kubernetes.io/service-name", SERVICE_NAME))
            .endMetadata()
            .withAddressType("IPv4")
            .withPorts(new EndpointPortBuilder().withName("thrift").withPort(port).build())
            .withEndpoints(new EndpointBuilder()
                .withAddresses("127.0.0.1")
                .withNewConditions().withReady(true).endConditions()
                .build())
            .build()).createOrReplace();
    MetastoreConf.setBoolVar(conf, ConfVars.EXECUTE_SET_UGI, false);
    return new HiveMetaStoreClient(conf);
  }
}
