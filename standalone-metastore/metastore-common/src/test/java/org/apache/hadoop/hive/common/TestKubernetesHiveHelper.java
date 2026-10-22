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

package org.apache.hadoop.hive.common;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServiceBuilder;
import io.fabric8.kubernetes.api.model.ServicePort;
import io.fabric8.kubernetes.api.model.ServicePortBuilder;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointBuilder;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointPortBuilder;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointSlice;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointSliceBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMixedDispatcher;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import io.fabric8.mockwebserver.Context;
import io.fabric8.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TestKubernetesHiveHelper {
  private static final String NS = "ns1";
  private static final String LABEL = KubernetesHiveHelper.DISCOVERY_LABEL;
  private static final String HMS = KubernetesHiveHelper.DISCOVERY_TYPE;

  private KubernetesMockServer server;
  private KubernetesClient client;

  @Before
  public void setUp() {
    server = new KubernetesMockServer(new Context(), new MockWebServer(), new HashMap<>(),
        new KubernetesMixedDispatcher(new HashMap<>()), false);
    server.init();
    client = server.createClient();
  }

  @After
  public void tearDown() {
    client.close();
    server.destroy();
  }

  private List<String> resolve(KubernetesHiveHelper.KubernetesHiveHelperBuilder builder) throws Exception {
    return builder.client(client).build().getServerUris();
  }

  private KubernetesHiveHelper.KubernetesHiveHelperBuilder inNamespace(String... namespaces) {
    return KubernetesHiveHelper.builder().namespaces(List.of(namespaces));
  }

  private void service(String namespace, String name, Map<String, String> annotations,
      boolean labeled, ServicePort... ports) {
    Service service = new ServiceBuilder()
        .withNewMetadata()
        .withName(name)
        .withNamespace(namespace)
        .withLabels(labeled ? Map.of(LABEL, HMS) : Map.of())
        .withAnnotations(annotations)
        .endMetadata()
        .withNewSpec()
        .withPorts(ports)
        .endSpec()
        .build();
    client.services().inNamespace(namespace).resource(service).create();
  }

  private ServicePort port(String name, int number) {
    return new ServicePortBuilder().withName(name).withPort(number).build();
  }

  private void endpointSlice(String namespace, String serviceName, String portName, int portNumber,
      Map<String, Boolean> addressReady) {
    EndpointSliceBuilder builder = new EndpointSliceBuilder()
        .withNewMetadata()
        .withName(serviceName + "-xyz")
        .withNamespace(namespace)
        .withLabels(Map.of("kubernetes.io/service-name", serviceName))
        .endMetadata()
        .withAddressType("IPv4")
        .withPorts(new EndpointPortBuilder().withName(portName).withPort(portNumber).build());
    for (Map.Entry<String, Boolean> e : addressReady.entrySet()) {
      builder.addToEndpoints(new EndpointBuilder()
          .withAddresses(e.getKey())
          .withNewConditions().withReady(e.getValue()).endConditions()
          .build());
    }
    EndpointSlice slice = builder.build();
    client.discovery().v1().endpointSlices().inNamespace(namespace).resource(slice).create();
  }

  @Test
  public void testSingleClusterResolved() throws Exception {
    service(NS, "hive-metastore", Map.of(), true, port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083,
        Map.of("10.0.0.1", true, "10.0.0.2", true));
    Assert.assertEquals(Set.of("thrift://10.0.0.1:9083", "thrift://10.0.0.2:9083"),
        Set.copyOf(resolve(inNamespace(NS))));
  }

  @Test
  public void testServiceWithoutLabelIgnored() throws Exception {
    service(NS, "hive-metastore", Map.of(), false, port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083, Map.of("10.0.0.1", true));
    Assert.assertTrue(resolve(inNamespace(NS)).isEmpty());
  }

  @Test
  public void testClusterSelectedByName() throws Exception {
    service(NS, "svc-a", Map.of(KubernetesHiveHelper.CLUSTER_KEY, "a"), true, port("thrift", 9083));
    endpointSlice(NS, "svc-a", "thrift", 9083, Map.of("10.0.0.1", true));
    service(NS, "svc-b", Map.of(KubernetesHiveHelper.CLUSTER_KEY, "b"), true, port("thrift", 9084));
    endpointSlice(NS, "svc-b", "thrift", 9084, Map.of("10.0.0.2", true));
    Assert.assertEquals(List.of("thrift://10.0.0.2:9084"),
        resolve(inNamespace(NS).cluster("b")));
  }

  @Test
  public void testDefaultClusterSelected() throws Exception {
    service(NS, "svc-a", Map.of(), true, port("thrift", 9083));
    endpointSlice(NS, "svc-a", "thrift", 9083, Map.of("10.0.0.1", true));
    service(NS, "svc-b", Map.of(KubernetesHiveHelper.DEFAULT_KEY, "true"), true, port("thrift", 9084));
    endpointSlice(NS, "svc-b", "thrift", 9084, Map.of("10.0.0.2", true));
    Assert.assertEquals(List.of("thrift://10.0.0.2:9084"), resolve(inNamespace(NS)));
  }

  @Test
  public void testAmbiguousClustersFail() {
    service(NS, "svc-a", Map.of(), true, port("thrift", 9083));
    service(NS, "svc-b", Map.of(), true, port("thrift", 9084));
    try {
      resolve(inNamespace(NS));
      Assert.fail("expected an exception for ambiguous clusters");
    } catch (Exception e) {
      Assert.assertTrue(e.getMessage(), e.getMessage().contains("svc-a"));
      Assert.assertTrue(e.getMessage(), e.getMessage().contains("svc-b"));
    }
  }

  @Test
  public void testUnknownClusterNameFails() {
    service(NS, "svc-a", Map.of(), true, port("thrift", 9083));
    try {
      resolve(inNamespace(NS).cluster("no-such"));
      Assert.fail("expected an exception for an unknown cluster");
    } catch (Exception e) {
      Assert.assertTrue(e.getMessage(), e.getMessage().contains("no-such"));
      Assert.assertTrue(e.getMessage(), e.getMessage().contains("svc-a"));
    }
  }

  @Test
  public void testPortByName() throws Exception {
    service(NS, "hive-metastore", Map.of(KubernetesHiveHelper.PORT_KEY, "thrift"), true,
        port("metrics", 9090), port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083, Map.of("10.0.0.1", true));
    Assert.assertEquals(List.of("thrift://10.0.0.1:9083"), resolve(inNamespace(NS)));
  }

  @Test
  public void testPortByNumber() throws Exception {
    service(NS, "hive-metastore", Map.of(KubernetesHiveHelper.PORT_KEY, "9084"), true,
        port("thrift", 9083), port("other", 9084));
    endpointSlice(NS, "hive-metastore", "other", 9084, Map.of("10.0.0.1", true));
    Assert.assertEquals(List.of("thrift://10.0.0.1:9084"), resolve(inNamespace(NS)));
  }

  @Test
  public void testFirstPortFallback() throws Exception {
    service(NS, "hive-metastore", Map.of(), true, port("binary", 9083));
    endpointSlice(NS, "hive-metastore", "binary", 9083, Map.of("10.0.0.1", true));
    Assert.assertEquals(List.of("thrift://10.0.0.1:9083"), resolve(inNamespace(NS)));
  }

  @Test
  public void testUnknownPortNameSkipsService() throws Exception {
    service(NS, "hive-metastore", Map.of(KubernetesHiveHelper.PORT_KEY, "no-such"), true,
        port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083, Map.of("10.0.0.1", true));
    Assert.assertTrue(resolve(inNamespace(NS)).isEmpty());
  }

  @Test
  public void testNotReadyEndpointsExcluded() throws Exception {
    service(NS, "hive-metastore", Map.of(), true, port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083,
        Map.of("10.0.0.1", true, "10.0.0.2", false));
    Assert.assertEquals(List.of("thrift://10.0.0.1:9083"), resolve(inNamespace(NS)));
  }

  @Test
  public void testHttpScheme() throws Exception {
    service(NS, "hive-metastore", Map.of(KubernetesHiveHelper.SCHEME_KEY, "http"), true,
        port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083, Map.of("10.0.0.1", true));
    Assert.assertEquals(List.of("http://10.0.0.1:9083"), resolve(inNamespace(NS)));
  }

  @Test
  public void testUnknownAnnotationSkipsService() throws Exception {
    service(NS, "hive-metastore", Map.of("hive.apache.org/typo", "x"), true, port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083, Map.of("10.0.0.1", true));
    Assert.assertTrue(resolve(inNamespace(NS)).isEmpty());
  }

  @Test
  public void testMultipleNamespaces() throws Exception {
    String other = "ns2";
    service(NS, "svc-a", Map.of(KubernetesHiveHelper.CLUSTER_KEY, "main"), true, port("thrift", 9083));
    endpointSlice(NS, "svc-a", "thrift", 9083, Map.of("10.0.0.1", true));
    service(other, "svc-b", Map.of(KubernetesHiveHelper.CLUSTER_KEY, "main"), true, port("thrift", 9083));
    endpointSlice(other, "svc-b", "thrift", 9083, Map.of("10.0.0.2", true));
    Assert.assertEquals(Set.of("thrift://10.0.0.1:9083", "thrift://10.0.0.2:9083"),
        Set.copyOf(resolve(inNamespace(NS, other))));
  }

  @Test
  public void testChangedEndpointsOnSecondRead() throws Exception {
    service(NS, "hive-metastore", Map.of(), true, port("thrift", 9083));
    endpointSlice(NS, "hive-metastore", "thrift", 9083, Map.of("10.0.0.1", true));
    Assert.assertEquals(List.of("thrift://10.0.0.1:9083"), resolve(inNamespace(NS)));
    client.discovery().v1().endpointSlices().inNamespace(NS)
        .withName("hive-metastore-xyz").delete();
    endpointSlice(NS, "hive-metastore", "thrift", 9083, Map.of("10.0.0.9", true));
    Assert.assertEquals(List.of("thrift://10.0.0.9:9083"), resolve(inNamespace(NS)));
  }
}
