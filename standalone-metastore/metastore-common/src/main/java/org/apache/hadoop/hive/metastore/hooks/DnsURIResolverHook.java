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
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import org.apache.hadoop.hive.metastore.HiveMetaException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DnsURIResolverHook. Resolves a metastore URI whose host names several servers, such as a
 * Kubernetes headless Service, into one URI per server, so that the client balances and fails
 * over between them itself (see metastore.thrift.uri.selection).
 *
 * <p>Every address the host resolves to becomes a URI with the same scheme, port and path. The
 * address is turned back into a host name through reverse DNS, so that Kerberos principals with
 * {@code _HOST} name the server: a StatefulSet pod behind a headless Service resolves to
 * {@code <pod>.<service>.<namespace>.svc.cluster.local}. An address without a reverse record
 * stays an address.
 *
 * <p>The client resolves again on every reconnect, so servers that come and go are picked up.
 */
public class DnsURIResolverHook implements URIResolverHook {
  private static final Logger LOG = LoggerFactory.getLogger(DnsURIResolverHook.class);

  @Override
  public List<URI> resolveURI(URI uri) throws HiveMetaException {
    String host = uri.getHost();
    if (host == null || host.isEmpty()) {
      return List.of(uri);
    }
    InetAddress[] addresses;
    try {
      addresses = lookup(host);
    } catch (UnknownHostException e) {
      throw new HiveMetaException("Cannot resolve metastore host " + host + " of " + uri, e);
    }
    // Sorted, so that a SEQUENTIAL selection always tries the servers in the same order.
    TreeSet<String> hosts = new TreeSet<>();
    for (InetAddress address : addresses) {
      hosts.add(hostNameOf(address));
    }
    List<URI> uris = new ArrayList<>(hosts.size());
    for (String h : hosts) {
      try {
        uris.add(new URI(uri.getScheme(), uri.getUserInfo(), h, uri.getPort(), uri.getPath(),
            uri.getQuery(), uri.getFragment()));
      } catch (URISyntaxException e) {
        throw new HiveMetaException("Cannot build a metastore URI for " + h + " from " + uri, e);
      }
    }
    LOG.debug("Resolved metastore URI {} into {}", uri, uris);
    return uris;
  }

  protected InetAddress[] lookup(String host) throws UnknownHostException {
    return InetAddress.getAllByName(host);
  }

  protected String hostNameOf(InetAddress address) {
    return address.getCanonicalHostName();
  }
}
