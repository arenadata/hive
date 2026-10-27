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

package org.apache.hadoop.hive.metastore.hooks;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

public class TestDnsURIResolverHook {

  /**
   * A resolver over a fixed table: host to addresses, and address to reverse name.
   */
  private static DnsURIResolverHook resolver(Map<String, List<String>> forward,
      Map<String, String> reverse) {
    return new DnsURIResolverHook() {
      @Override
      protected InetAddress[] lookup(String host) throws UnknownHostException {
        List<String> ips = forward.get(host);
        if (ips == null) {
          throw new UnknownHostException(host);
        }
        InetAddress[] addresses = new InetAddress[ips.size()];
        for (int i = 0; i < ips.size(); i++) {
          addresses[i] = InetAddress.getByName(ips.get(i));
        }
        return addresses;
      }

      @Override
      protected String hostNameOf(InetAddress address) {
        return reverse.getOrDefault(address.getHostAddress(), address.getHostAddress());
      }
    };
  }

  @Test
  public void testHeadlessServiceResolvedToPods() throws Exception {
    DnsURIResolverHook hook = resolver(
        Map.of("hms.ns.svc.cluster.local", List.of("10.0.0.2", "10.0.0.1")),
        Map.of("10.0.0.1", "hms-0.hms.ns.svc.cluster.local",
            "10.0.0.2", "hms-1.hms.ns.svc.cluster.local"));
    Assert.assertEquals(List.of(
            new URI("thrift://hms-0.hms.ns.svc.cluster.local:9083"),
            new URI("thrift://hms-1.hms.ns.svc.cluster.local:9083")),
        hook.resolveURI(new URI("thrift://hms.ns.svc.cluster.local:9083")));
  }

  @Test
  public void testAddressWithoutReverseRecordStaysAddress() throws Exception {
    DnsURIResolverHook hook = resolver(Map.of("hms", List.of("10.0.0.1")), Map.of());
    Assert.assertEquals(List.of(new URI("thrift://10.0.0.1:9083")),
        hook.resolveURI(new URI("thrift://hms:9083")));
  }

  @Test
  public void testHttpPathKept() throws Exception {
    DnsURIResolverHook hook = resolver(Map.of("hms", List.of("10.0.0.1")),
        Map.of("10.0.0.1", "hms-0.hms"));
    Assert.assertEquals(List.of(new URI("http://hms-0.hms:9001/metastore")),
        hook.resolveURI(new URI("http://hms:9001/metastore")));
  }

  @Test
  public void testDuplicateNamesCollapsed() throws Exception {
    DnsURIResolverHook hook = resolver(Map.of("hms", List.of("10.0.0.1", "10.0.0.2")),
        Map.of("10.0.0.1", "hms-0.hms", "10.0.0.2", "hms-0.hms"));
    Assert.assertEquals(List.of(new URI("thrift://hms-0.hms:9083")),
        hook.resolveURI(new URI("thrift://hms:9083")));
  }

  @Test
  public void testIpv6Address() throws Exception {
    DnsURIResolverHook hook = resolver(Map.of("hms", List.of("fd00::1")), Map.of());
    List<URI> uris = hook.resolveURI(new URI("thrift://hms:9083"));
    Assert.assertEquals(1, uris.size());
    Assert.assertEquals(9083, uris.get(0).getPort());
    Assert.assertEquals("thrift", uris.get(0).getScheme());
    Assert.assertTrue(uris.get(0).getHost(), uris.get(0).getHost().startsWith("[fd00:"));
  }

  @Test
  public void testUnknownHostKeptAsIs() throws Exception {
    URI uri = new URI("thrift://no-such:9083");
    Assert.assertEquals(List.of(uri), resolver(Map.of(), Map.of()).resolveURI(uri));
  }

  @Test
  public void testPodNamesOrderedByOrdinal() throws Exception {
    DnsURIResolverHook hook = resolver(
        Map.of("hms", List.of("10.0.0.10", "10.0.0.2")),
        Map.of("10.0.0.10", "hms-10.hms", "10.0.0.2", "hms-2.hms"));
    Assert.assertEquals(List.of(
            new URI("thrift://hms-2.hms:9083"),
            new URI("thrift://hms-10.hms:9083")),
        hook.resolveURI(new URI("thrift://hms:9083")));
  }

  @Test
  public void testNamesDifferingOnlyInCaseCollapsed() throws Exception {
    DnsURIResolverHook hook = resolver(Map.of("hms", List.of("10.0.0.1", "10.0.0.2")),
        Map.of("10.0.0.1", "HMS-0.hms", "10.0.0.2", "hms-0.hms"));
    Assert.assertEquals(List.of(new URI("thrift://HMS-0.hms:9083")),
        hook.resolveURI(new URI("thrift://hms:9083")));
  }

  @Test
  public void testUriWithoutHostUntouched() throws Exception {
    URI uri = new URI("thrift:///");
    Assert.assertEquals(List.of(uri), resolver(Map.of(), Map.of()).resolveURI(uri));
  }
}
