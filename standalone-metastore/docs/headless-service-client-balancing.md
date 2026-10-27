<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to you under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# Metastore behind a Kubernetes headless Service: client-side balancing

Metastore servers running in Kubernetes can be reached through a headless
Service, with the metastore client balancing and failing over between the
servers itself. The client needs only DNS: no ZooKeeper, no access to the
Kubernetes API, no extra dependencies.

## How it works

A headless Service (`clusterIP: None`) has no virtual IP: its DNS name resolves
to the addresses of its ready pods. On its own the metastore client connects to
one address of a host and never tries the others, so
`org.apache.hadoop.hive.metastore.hooks.DnsURIResolverHook`, plugged in as the
URI resolver, turns the host into one URI per server:

1. Every address the host of each `hive.metastore.uris` entry resolves to
   becomes a URI with the same scheme, port and path.
2. Each address is turned back into a host name through reverse DNS. A
   StatefulSet pod behind the headless Service resolves to
   `<pod>.<service>.<namespace>.svc.cluster.local`; an address without a reverse
   record stays an address.
3. The client orders the URIs as `hive.metastore.uri.selection` says (`RANDOM`
   shuffles them) and connects to the first one that answers.
4. On every reconnect the client resolves the host again, so servers that were
   added, removed or rescheduled to a new address are picked up.

A host that does not resolve at all is left as is, so that the failure surfaces
as a connection error, which the client retries, instead of aborting the
reconnect.

```
hive.metastore.uris = thrift://hms.hive.svc.cluster.local:9083
                        |
                        |  DNS A records (ready pods only)
                        v
      10.0.0.1                   10.0.0.2
                        |
                        |  reverse DNS (PTR)
                        v
thrift://hms-0.hms.hive.svc.cluster.local:9083
thrift://hms-1.hms.hive.svc.cluster.local:9083
```

## Server side

Run the metastore as a StatefulSet whose `serviceName` is the headless Service.
That gives every pod a stable DNS name, which reverse DNS returns and which
Kerberos needs (see below).

```yaml
apiVersion: v1
kind: Service
metadata:
  name: hms
  namespace: hive
spec:
  clusterIP: None
  selector:
    app: hive-metastore
  ports:
    - name: thrift
      port: 9083
      targetPort: 9083
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: hms
  namespace: hive
spec:
  serviceName: hms
  replicas: 2
  selector:
    matchLabels:
      app: hive-metastore
  template:
    metadata:
      labels:
        app: hive-metastore
    spec:
      containers:
        - name: metastore
          image: apache/hive:<version>
          env:
            - name: SERVICE_NAME
              value: metastore
          ports:
            - name: thrift
              containerPort: 9083
          readinessProbe:
            tcpSocket:
              port: thrift
```

Only ready pods are published in DNS (unless the Service sets
`publishNotReadyAddresses: true`), so give the pods a readiness probe.

With more than one server, have only one of them run the housekeeping tasks:
set `metastore.housekeeping.leader.election` or
`metastore.housekeeping.leader.hostname`.

## Client side

```xml
<property>
  <name>hive.metastore.uris</name>
  <value>thrift://hms.hive.svc.cluster.local:9083</value>
</property>
<property>
  <name>hive.metastore.uri.resolver</name>
  <value>org.apache.hadoop.hive.metastore.hooks.DnsURIResolverHook</value>
</property>
<property>
  <name>hive.metastore.uri.selection</name>
  <value>RANDOM</value>
</property>
<property>
  <!-- Reconnect now and then, so that the load spreads over new servers. -->
  <name>hive.metastore.client.socket.lifetime</name>
  <value>600s</value>
</property>
```

| Property | Role here |
|----------|-----------|
| `hive.metastore.uris` | The headless Service name; several entries are each resolved. |
| `hive.metastore.uri.resolver` | Turns each host into one URI per server. |
| `hive.metastore.uri.selection` | `RANDOM` (default) spreads clients over servers; `SEQUENTIAL` tries them in pod name order (hms-2 before hms-10). |
| `hive.metastore.client.socket.lifetime` | Connections are long-lived; a finite lifetime makes clients reconnect, resolve again and rebalance. `0s` (default) keeps a connection forever. |
| `hive.metastore.failure.retries`, `hive.metastore.client.connect.retry.delay` | How many rounds over the servers a client makes, and the pause between them, before it gives up. |

The http transport (`hive.metastore.client.thrift.transport.mode=http`) works
the same way; the path of the URI is kept.

## Kerberos

The client builds the server principal from the host of the URI it connects to:
with `hive.metastore.kerberos.principal=hive/_HOST@REALM`, a client connecting to
`hms-0.hms.hive.svc.cluster.local` expects
`hive/hms-0.hms.hive.svc.cluster.local@REALM`. So:

- run the metastore as a StatefulSet behind the headless Service, so that
  reverse DNS returns the pod's stable name;
- give every pod a keytab with its own principal
  (`hive/hms-0.hms.hive.svc.cluster.local@REALM`,
  `hive/hms-1.hms.hive.svc.cluster.local@REALM`, ...).

Pods of a Deployment have no stable name: reverse DNS returns names like
`10-0-0-1.hms.hive.svc.cluster.local`, which change on every restart and cannot
have principals. Use a StatefulSet when Kerberos is on.

## DNS caching

The JVM caches lookups: successful ones for `networkaddress.cache.ttl` seconds
(30 by default), failed ones for `networkaddress.cache.negative.ttl` (10). A
client sees a new or moved server only after the cache entry expires and the
client reconnects. Lower these security properties (in
`$JAVA_HOME/conf/security/java.security`, or a file passed with
`-Djava.security.properties=`) if servers must be picked up faster.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `Cannot resolve metastore host ...` in the log, then connection failures | The name does not resolve: wrong name or namespace, or no pod is ready. The URI is kept as is, so the connection failure is retried like any other. |
| Clients connect to one server only | `hive.metastore.uri.resolver` is not set, or the Service is not headless (a ClusterIP Service resolves to its single virtual IP). |
| `GSS initiate failed` / `Server not found in Kerberos database` | The principal built from the host is not in the keytab: check what reverse DNS returns for the pod IP (`nslookup <pod-ip>`) and that it is a StatefulSet pod name. |
| Load stays on the old servers after scaling up | Connections are long-lived; set `hive.metastore.client.socket.lifetime`. |
