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

# hive-metastore Helm chart

Deploys one Hive Metastore (HMS) per namespace: a StatefulSet behind a headless
Service, for clients that balance between its pods with `DnsURIResolverHook`
(see `standalone-metastore/docs/headless-service-client-balancing.md`). The
metastore database is either the chart's own PostgreSQL (`postgres.enabled=true`)
or an external one.

## Install

With the chart's own PostgreSQL:

```bash
helm install hms standalone-metastore/packaging/src/helm/hive-metastore -n data \
  --set image.repository=<registry>/hive-metastore \
  --set image.tag=<tag> \
  --set postgres.enabled=true \
  --set warehouseDir=s3a://warehouse/
```

The PostgreSQL is a single server with a persistent volume: the metastore
servers are highly available, the database is not. Use an external database
where that matters:

```bash
kubectl -n data create secret generic hms-db --from-literal=password=<password>

helm install hms standalone-metastore/packaging/src/helm/hive-metastore -n data \
  --set image.repository=<registry>/hive-metastore \
  --set image.tag=<tag> \
  --set database.url=jdbc:postgresql://pg:5432/metastore \
  --set database.driver=org.postgresql.Driver \
  --set database.user=hive \
  --set database.passwordSecret.name=hms-db \
  --set warehouseDir=s3a://warehouse/
```

Clients then connect with:

| Property | Value |
| --- | --- |
| `hive.metastore.uris` | `thrift://hive-metastore.<namespace>.svc.cluster.local:9083` |
| `hive.metastore.uri.resolver` | `org.apache.hadoop.hive.metastore.hooks.DnsURIResolverHook` |
| `hive.metastore.uri.selection` | `RANDOM` |
| `hive.metastore.client.socket.lifetime` | `600s` |

## One per namespace

Every resource has a fixed name, not prefixed with the release: `hive-metastore`
(Service, StatefulSet, PodDisruptionBudget), `hive-metastore-config`,
`hive-metastore-schema-<revision>` (Job) and `hive-metastore-postgres`. A client
therefore needs only the namespace, and a second release in a namespace that
already has one fails on these names without touching the first.

## Resources

| Resource | Name | Notes |
| --- | --- | --- |
| Job | `hive-metastore-schema-<revision>` | `schematool -initOrUpgradeSchema`, after waiting for the database; run anew on every install and upgrade |
| Secret | `hive-metastore-config` | `metastore-site.xml`, and `core-site.xml` when `coreSite` or Kerberos is set; a Secret because it names the database and the authentication setup |
| Service | `hive-metastore` | Headless; its name resolves to the ready pods only |
| StatefulSet | `hive-metastore` | Pods `hive-metastore-<N>.hive-metastore.<namespace>.svc.cluster.local`; each waits in an init container until the schema is there; restarted when the configuration changes |
| PodDisruptionBudget | `hive-metastore` | `maxUnavailable: 1` |
| Secret, Service, StatefulSet (with `postgres.enabled`) | `hive-metastore-postgres` | PostgreSQL with a `ReadWriteOnce` volume; the Secret holds the generated password |
| Pod (`helm test`) | `hive-metastore-test` | Checks that every address of the Service answers on the thrift port |

## Values

| Value | Default | Description |
| --- | --- | --- |
| `image.repository`, `image.tag` | required | Image built from `standalone-metastore/packaging/src/docker/Dockerfile.client-balancing` |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `replicas` | `2` | The housekeeping leader is elected through a Hive lock |
| `port` | `9083` | Thrift port of the servers and the Service |
| `postgres.enabled` | `false` | Deploys the chart's own PostgreSQL; the `database.*` values are then not used |
| `postgres.image` | `postgres:16` | |
| `postgres.database`, `postgres.user` | `metastore`, `hive` | |
| `postgres.password` | `""` | Generated once when empty, then kept across upgrades |
| `postgres.existingSecret`, `.existingSecretKey` | `""`, `password` | An existing Secret with the password instead |
| `postgres.persistence.enabled`, `.size`, `.storageClass` | `true`, `8Gi`, default class | Without persistence the data is lost with the pod |
| `postgres.resources` | `{}` | |
| `database.type` | `postgres` | `schematool -dbType` |
| `database.url`, `database.driver`, `database.user` | required without `postgres.enabled` | JDBC connection |
| `database.passwordSecret.name` | required without `postgres.enabled` | Existing Secret with the database password |
| `database.passwordSecret.key` | `password` | |
| `warehouseDir` | required | `metastore.warehouse.dir` |
| `extraJars` | `[]` | URLs of jars added to the image's `lib`, such as a JDBC driver the image lacks |
| `metastoreSite` | `{}` | Properties merged over the chart's `metastore-site.xml` |
| `coreSite` | `{}` | Properties of `core-site.xml`; without any, the image's own stays |
| `heap` | `1g` | `-Xmx` of the servers and the schema Job |
| `extraJavaOpts` | `""` | Extra JVM options of the servers |
| `auth.type` | `NOSASL` | How clients authenticate: `NOSASL`, `KERBEROS`, `LDAP`, `CONFIG` or `CUSTOM` (see below) |
| `auth.kerberos.principal` | `hive/_HOST@EXAMPLE.COM` | `_HOST` becomes each pod's name |
| `auth.kerberos.keytabSecret.name`, `.key` | required with `KERBEROS`, `hive.keytab` | One keytab with a principal for every pod ordinal |
| `auth.kerberos.krb5ConfigMap.name`, `.key` | required with `KERBEROS`, `krb5.conf` | |
| `auth.ldap.url` | required with `LDAP` | `metastore.authentication.ldap.url` |
| `auth.ldap.baseDN`, `.userDNPattern` | `""` | Other `metastore.authentication.ldap.*` properties go into `metastoreSite` |
| `auth.ldap.bindDN`, `.bindPasswordSecret.name`, `.key` | `""`, `""`, `password` | Bind user for searches and the Secret with its password |
| `auth.config.username`, `.passwordSecret.name`, `.key` | required with `CONFIG`, `password` | The one user and password the metastore accepts |
| `auth.custom.className` | required with `CUSTOM` | A `MetaStorePasswdAuthenticationProvider`; its jar goes into `extraJars` |
| `schemaJob.backoffLimit` | `3` | |
| `schemaJob.activeDeadlineSeconds` | `600` | |
| `schemaJob.resources` | `{}` | |
| `readinessProbe`, `livenessProbe` | 15s/10s/3, 60s/30s/5 | TCP probes on the thrift port: initial delay, period, failure threshold |
| `podDisruptionBudget.enabled`, `.maxUnavailable` | `true`, `1` | |
| `resources`, `nodeSelector`, `tolerations` | empty | |
| `affinity` | `{}` | Without one, the pods prefer different nodes |
| `podAnnotations`, `podLabels` | `{}` | |
| `serviceAccountName` | `""` | |
| `podSecurityContext` | uid, gid and fsGroup 1000 | The image's `hive` user |

## Authentication

| `auth.type` | Server checks | Client properties |
| --- | --- | --- |
| `NOSASL` | Nothing | None |
| `KERBEROS` | Kerberos ticket (SASL GSSAPI) | `hive.metastore.sasl.enabled=true`, `hive.metastore.kerberos.principal=hive/_HOST@REALM` |
| `LDAP` | User and password against LDAP (SASL PLAIN) | `hive.metastore.client.auth.mode=PLAIN`, `hive.metastore.client.plain.username=<user>` |
| `CONFIG` | User and password against `auth.config` (SASL PLAIN) | Same as `LDAP` |
| `CUSTOM` | User and password through `auth.custom.className` (SASL PLAIN) | Same as `LDAP` |

With PLAIN the client reads the password of `<user>` from the Hadoop credential
provider (`hadoop.security.credential.provider.path`), with the user name as the
alias. The password then travels in clear text, unless TLS is set up on the
server (`metastore.use.SSL` and a keystore, through `metastoreSite`) and the
clients.

Passwords never go into the generated configuration: the chart reads them from
the Secrets the values name and passes them to the server as system properties.

## Upgrade and uninstall

`helm upgrade` runs a new schema Job, and the restarted servers wait for it, so
a new image upgrades the schema first. The servers that keep running are not
interrupted, and a pod that fails to start with a new configuration leaves the
others serving. Kubernetes deletes a finished schema Job after
`schemaJob.ttlSecondsAfterFinished` (a day), including the Job of a failed
upgrade, which no later revision owns.

The schema Job is not a Helm hook. A `pre-install` hook would run before the
chart's own PostgreSQL exists, and a `post-install` hook runs only after
`helm --wait` sees the metastore pods Ready, while they wait for the schema.

`helm uninstall` removes the metastore and the schema Job. The database is left
as is: an external one is not touched, and with `postgres.enabled` the volume
`data-hive-metastore-postgres-0` and the Secret `hive-metastore-postgres` stay,
so that a new install opens the same database. Delete both to start afresh:

```bash
kubectl -n <namespace> delete pvc/data-hive-metastore-postgres-0 secret/hive-metastore-postgres
```

## Images without the needed jars

An image built from `Dockerfile.client-balancing` has the PostgreSQL driver and
the YARN jars the housekeeping tasks need. The upstream `apache/hive:standalone-metastore-*`
images do not: their log shows `ClassNotFoundException:
org.apache.hadoop.yarn.util.SystemClock` and housekeeping does not run. With
such an image, add the jars, and the JDBC driver, through `extraJars`:

```yaml
extraJars:
  - https://repo1.maven.org/maven2/org/postgresql/postgresql/42.7.5/postgresql-42.7.5.jar
  - https://repo1.maven.org/maven2/org/apache/hadoop/hadoop-yarn-api/3.4.1/hadoop-yarn-api-3.4.1.jar
  - https://repo1.maven.org/maven2/org/apache/hadoop/hadoop-yarn-common/3.4.1/hadoop-yarn-common-3.4.1.jar
```

Match the Hadoop version of the image (3.4.1 for `standalone-metastore-4.2.0`).
