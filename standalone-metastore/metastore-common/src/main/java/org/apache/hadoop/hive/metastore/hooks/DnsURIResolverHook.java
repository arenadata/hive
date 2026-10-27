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
 * over between them itself (see metastore.thrift.uri.selection). Meant for Kubernetes: the host
 * of every URI is replaced by what reverse DNS says for it.
 *
 * <p>Every address the host resolves to becomes a URI with the same scheme, port and path. The
 * address is turned back into a host name through reverse DNS, so that Kerberos principals with
 * {@code _HOST} name the server: a StatefulSet pod behind a headless Service resolves to
 * {@code <pod>.<service>.<namespace>.svc.cluster.local}. An address without a reverse record
 * stays an address.
 *
 * <p>A host that does not resolve at all is left as is, so that the failure surfaces as a
 * connection error, which the client retries, instead of aborting the reconnect. The client
 * resolves again on every reconnect, so servers that come and go are picked up.
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
      LOG.warn("Cannot resolve metastore host {} of {}; keeping the URI as is", host, uri);
      return List.of(uri);
    }
    // Sorted, so that a SEQUENTIAL selection always tries the servers in the same order.
    TreeSet<String> hosts = new TreeSet<>(DnsURIResolverHook::compareHostNames);
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

  /**
   * Compares host names case-insensitively, with runs of digits compared as numbers, so that
   * pod names order by their ordinal: hms-2 sorts before hms-10.
   */
  static int compareHostNames(String a, String b) {
    int i = 0;
    int j = 0;
    while (i < a.length() && j < b.length()) {
      char ca = a.charAt(i);
      char cb = b.charAt(j);
      if (Character.isDigit(ca) && Character.isDigit(cb)) {
        int endA = i;
        int endB = j;
        while (endA < a.length() && Character.isDigit(a.charAt(endA))) {
          endA++;
        }
        while (endB < b.length() && Character.isDigit(b.charAt(endB))) {
          endB++;
        }
        String numA = stripLeadingZeros(a.substring(i, endA));
        String numB = stripLeadingZeros(b.substring(j, endB));
        if (numA.length() != numB.length()) {
          return numA.length() - numB.length();
        }
        int cmp = numA.compareTo(numB);
        if (cmp != 0) {
          return cmp;
        }
        i = endA;
        j = endB;
      } else {
        int cmp = Character.compare(Character.toLowerCase(ca), Character.toLowerCase(cb));
        if (cmp != 0) {
          return cmp;
        }
        i++;
        j++;
      }
    }
    return (a.length() - i) - (b.length() - j);
  }

  private static String stripLeadingZeros(String digits) {
    int i = 0;
    while (i < digits.length() - 1 && digits.charAt(i) == '0') {
      i++;
    }
    return digits.substring(i);
  }

  protected InetAddress[] lookup(String host) throws UnknownHostException {
    return InetAddress.getAllByName(host);
  }

  protected String hostNameOf(InetAddress address) {
    return address.getCanonicalHostName();
  }
}
