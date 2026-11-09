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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.fabric8.kubernetes.api.model.IntOrString;
import io.fabric8.kubernetes.api.model.Service;
import io.fabric8.kubernetes.api.model.ServicePort;
import io.fabric8.kubernetes.api.model.discovery.v1.Endpoint;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointConditions;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointPort;
import io.fabric8.kubernetes.api.model.discovery.v1.EndpointSlice;
import io.fabric8.kubernetes.client.ConfigBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KubernetesHiveHelper. A helper class to hold Kubernetes related configuration and to fetch
 * metastore server URIs from Kubernetes for clients, when dynamic service discovery mode is
 * "k8s".
 *
 * <p>A Kubernetes Service labeled {@code app.apache.org/discovery: HMS} is a metastore cluster;
 * the endpoints behind it (EndpointSlices, ready addresses only) are the servers. The Service
 * says how to reach them through annotations under {@code hive.apache.org/}:
 *
 * <pre>
 *   scheme    thrift (default) or http
 *   port      the thrift endpoint's port: a number, which is the Service port as kubectl shows
 *             it, or a port name; the Service port named "thrift" unless set, or its first port
 *   cluster   the logical cluster name; the Service name unless set
 *   default   "true" on the one cluster clients who name nothing get
 * </pre>
 *
 * A Service with an unknown {@code hive.apache.org/} key or a port it does not have is skipped
 * with a warning and costs only itself.
 */
public class KubernetesHiveHelper implements AutoCloseable {
  public static final Logger LOG = LoggerFactory.getLogger(KubernetesHiveHelper.class.getName());

  public static final String DISCOVERY_LABEL = "app.apache.org/discovery";
  public static final String DISCOVERY_TYPE = "HMS";
  public static final String ANNOTATION_PREFIX = "hive.apache.org/";
  public static final String SCHEME_KEY = ANNOTATION_PREFIX + "scheme";
  public static final String PORT_KEY = ANNOTATION_PREFIX + "port";
  public static final String CLUSTER_KEY = ANNOTATION_PREFIX + "cluster";
  public static final String DEFAULT_KEY = ANNOTATION_PREFIX + "default";
  public static final String DEFAULT_PORT_NAME = "thrift";

  private static final Set<String> KNOWN_KEYS =
      Set.of(SCHEME_KEY, PORT_KEY, CLUSTER_KEY, DEFAULT_KEY);
  private static final Set<String> KNOWN_SCHEMES = Set.of("thrift", "http");
  private static final String SERVICE_NAME_LABEL = "kubernetes.io/service-name";

  private final KubernetesClient client;
  private final boolean ownsClient;
  private final List<String> namespaces;
  private final String cluster;

  private KubernetesHiveHelper(KubernetesHiveHelperBuilder builder) {
    this.namespaces = builder.namespaces;
    this.cluster = builder.cluster;
    if (builder.client != null) {
      this.client = builder.client;
      this.ownsClient = false;
    } else {
      this.ownsClient = true;
      if (builder.masterUrl != null && !builder.masterUrl.isEmpty()) {
        this.client = new KubernetesClientBuilder()
            .withConfig(new ConfigBuilder().withMasterUrl(builder.masterUrl).build()).build();
      } else {
        this.client = new KubernetesClientBuilder().build();
      }
    }
  }

  /**
   * Closes the Kubernetes client this helper created. A client handed in through
   * {@link KubernetesHiveHelperBuilder#client(KubernetesClient)} belongs to the caller and is
   * left open.
   */
  @Override
  public void close() {
    if (ownsClient) {
      client.close();
    }
  }

  /**
   * KubernetesHiveHelperBuilder. A builder class to initialize KubernetesHiveHelper.
   */
  public static class KubernetesHiveHelperBuilder {
    private List<String> namespaces = List.of();
    private String cluster = null;
    private String masterUrl = null;
    private KubernetesClient client = null;

    public KubernetesHiveHelper build() {
      return new KubernetesHiveHelper(this);
    }

    public KubernetesHiveHelperBuilder namespaces(List<String> namespaces) {
      this.namespaces = namespaces;
      return this;
    }

    public KubernetesHiveHelperBuilder cluster(String cluster) {
      this.cluster = cluster;
      return this;
    }

    public KubernetesHiveHelperBuilder masterUrl(String masterUrl) {
      this.masterUrl = masterUrl;
      return this;
    }

    public KubernetesHiveHelperBuilder client(KubernetesClient client) {
      this.client = client;
      return this;
    }
  }

  public static KubernetesHiveHelperBuilder builder() {
    return new KubernetesHiveHelperBuilder();
  }

  /**
   * Returns the URIs (scheme://host:port) of every ready endpoint of the selected metastore
   * cluster, or an empty list when no such endpoint exists.
   */
  public List<String> getServerUris() throws Exception {
    Map<String, List<Service>> clusters = new LinkedHashMap<>();
    for (String namespace : effectiveNamespaces()) {
      for (Service service : client.services().inNamespace(namespace)
          .withLabel(DISCOVERY_LABEL, DISCOVERY_TYPE).list().getItems()) {
        String name = service.getMetadata().getName();
        Map<String, String> annotations = annotationsOf(service);
        String unknown = unknownKey(annotations);
        if (unknown != null) {
          LOG.warn("Skipping Service {}/{}: '{}' is not a metastore discovery key; expected one of {}",
              namespace, name, unknown, KNOWN_KEYS);
          continue;
        }
        String clusterName = Optional.ofNullable(annotations.get(CLUSTER_KEY))
            .map(String::trim).filter(n -> !n.isEmpty()).orElse(name);
        clusters.computeIfAbsent(clusterName, k -> new ArrayList<>()).add(service);
      }
    }
    if (clusters.isEmpty()) {
      return List.of();
    }
    List<Service> selected = selectCluster(clusters);
    List<String> uris = new ArrayList<>();
    for (Service service : selected) {
      uris.addAll(urisOf(service));
    }
    return uris;
  }

  private List<String> effectiveNamespaces() {
    if (namespaces != null && !namespaces.isEmpty()) {
      return namespaces;
    }
    String own = client.getNamespace();
    if (own == null || own.isEmpty()) {
      throw new IllegalStateException("Cannot tell the namespace to look for metastore Services in; "
          + "set metastore.kubernetes.namespaces");
    }
    return List.of(own);
  }

  private List<Service> selectCluster(Map<String, List<Service>> clusters) {
    if (cluster != null && !cluster.isEmpty()) {
      List<Service> found = clusters.get(cluster);
      if (found == null) {
        throw new IllegalStateException("No metastore cluster named '" + cluster
            + "' discovered in Kubernetes; available clusters: " + clusters.keySet());
      }
      return found;
    }
    if (clusters.size() == 1) {
      return clusters.values().iterator().next();
    }
    List<String> defaults = new ArrayList<>();
    for (Map.Entry<String, List<Service>> e : clusters.entrySet()) {
      if (e.getValue().stream().anyMatch(s -> Boolean.parseBoolean(
          annotationsOf(s).getOrDefault(DEFAULT_KEY, "false")))) {
        defaults.add(e.getKey());
      }
    }
    if (defaults.size() == 1) {
      return clusters.get(defaults.get(0));
    }
    throw new IllegalStateException("More than one metastore cluster discovered in Kubernetes: "
        + clusters.keySet() + (defaults.isEmpty()
        ? "; set metastore.kubernetes.cluster or mark one Service with '" + DEFAULT_KEY + ": \"true\"'"
        : "; more than one is marked '" + DEFAULT_KEY + ": \"true\"': " + defaults));
  }

  private List<String> urisOf(Service service) {
    String namespace = service.getMetadata().getNamespace();
    String name = service.getMetadata().getName();
    Map<String, String> annotations = annotationsOf(service);
    String scheme = annotations.getOrDefault(SCHEME_KEY, "thrift").toLowerCase(Locale.ROOT).trim();
    if (!KNOWN_SCHEMES.contains(scheme)) {
      LOG.warn("Skipping Service {}/{}: '{}' is not a known scheme; expected thrift or http",
          namespace, name, scheme);
      return List.of();
    }
    Optional<ResolvedPort> wanted = resolvePort(service, annotations.get(PORT_KEY));
    if (wanted.isEmpty()) {
      return List.of();
    }
    List<String> uris = new ArrayList<>();
    for (EndpointSlice slice : client.discovery().v1().endpointSlices().inNamespace(namespace)
        .withLabel(SERVICE_NAME_LABEL, name).list().getItems()) {
      Optional<Integer> port = slicePort(slice, wanted.get());
      if (port.isEmpty()) {
        LOG.warn("Skipping EndpointSlice {}/{} of Service {}/{}: it has no {}", namespace,
            slice.getMetadata().getName(), namespace, name, wanted.get());
        continue;
      }
      for (Endpoint endpoint : slice.getEndpoints()) {
        if (!isReady(endpoint)) {
          continue;
        }
        for (String address : endpoint.getAddresses()) {
          uris.add(scheme + "://" + address + ":" + port.get());
        }
      }
    }
    return uris;
  }

  /**
   * The Service port the annotation names: a number, which is matched against the Service port
   * numbers, or a port name; without the annotation the Service port named "thrift", or the
   * Service's first port. A Service asking for a port it does not have is a typo and is skipped,
   * as one with an unknown key is.
   */
  private Optional<ResolvedPort> resolvePort(Service service, String requested) {
    String namespace = service.getMetadata().getNamespace();
    String name = service.getMetadata().getName();
    List<ServicePort> ports =
        service.getSpec() == null || service.getSpec().getPorts() == null
            ? List.of() : service.getSpec().getPorts();
    if (requested != null && !requested.trim().isEmpty()) {
      String wanted = requested.trim();
      Optional<ServicePort> found = wanted.chars().allMatch(Character::isDigit)
          ? ports.stream().filter(p -> p.getPort() != null
              && wanted.equals(String.valueOf(p.getPort()))).findFirst()
          : ports.stream().filter(p -> wanted.equals(p.getName())).findFirst();
      if (found.isEmpty()) {
        LOG.warn("Skipping Service {}/{}: the Service has no port {}", namespace, name, wanted);
        return Optional.empty();
      }
      return Optional.of(resolved(found.get()));
    }
    if (ports.isEmpty()) {
      LOG.warn("Skipping Service {}/{}: the Service has no ports", namespace, name);
      return Optional.empty();
    }
    ServicePort port = ports.stream().filter(p -> DEFAULT_PORT_NAME.equals(p.getName()))
        .findFirst().orElse(ports.get(0));
    return Optional.of(resolved(port));
  }

  /**
   * The port number of the endpoint behind the Service port, in the EndpointSlice of the Service:
   * a named Service port is found by its name, which EndpointSlices carry over; an unnamed one by
   * its target port.
   */
  private Optional<Integer> slicePort(EndpointSlice slice, ResolvedPort wanted) {
    if (slice.getPorts() == null) {
      return Optional.empty();
    }
    return slice.getPorts().stream()
        .filter(p -> wanted.name != null
            ? wanted.name.equals(p.getName())
            : wanted.targetPort != null && wanted.targetPort.equals(p.getPort()))
        .map(EndpointPort::getPort)
        .findFirst();
  }

  private boolean isReady(Endpoint endpoint) {
    // A nil ready condition means ready; a terminating endpoint is not.
    EndpointConditions conditions = endpoint.getConditions();
    if (conditions == null) {
      return true;
    }
    boolean ready = conditions.getReady() == null || conditions.getReady();
    boolean terminating = Boolean.TRUE.equals(conditions.getTerminating());
    return ready && !terminating;
  }

  private static ResolvedPort resolved(ServicePort port) {
    return new ResolvedPort(port.getName(), port.getPort(), targetPortOf(port));
  }

  /**
   * The pod port behind a Service port: its targetPort, which defaults to the port itself. A named
   * targetPort is not resolved here; it yields null, as an unnamed Service port cannot then be
   * matched to its EndpointSlice port.
   */
  private static Integer targetPortOf(ServicePort port) {
    IntOrString target = port.getTargetPort();
    if (target == null) {
      return port.getPort();
    }
    return target.getIntVal();
  }

  private static Map<String, String> annotationsOf(Service service) {
    Map<String, String> annotations = service.getMetadata().getAnnotations();
    return annotations != null ? annotations : Map.of();
  }

  private static String unknownKey(Map<String, String> annotations) {
    for (String key : annotations.keySet()) {
      if (key.startsWith(ANNOTATION_PREFIX) && !KNOWN_KEYS.contains(key)) {
        return key;
      }
    }
    return null;
  }

  private static final class ResolvedPort {
    private final String name;
    private final Integer port;
    private final Integer targetPort;

    private ResolvedPort(String name, Integer port, Integer targetPort) {
      this.name = name;
      this.port = port;
      this.targetPort = targetPort;
    }

    @Override
    public String toString() {
      return name != null ? "port named " + name : "port " + port;
    }
  }
}
