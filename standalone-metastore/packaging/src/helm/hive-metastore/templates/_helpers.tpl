{{/*
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
*/}}

{{/*
The name of every resource. It is fixed, not prefixed with the release, so that every namespace has
at most one metastore and clients find it at the same address in any namespace.
*/}}
{{- define "hive-metastore.name" -}}
hive-metastore
{{- end }}

{{- define "hive-metastore.postgresName" -}}
hive-metastore-postgres
{{- end }}

{{/* Labels of a component: metastore (the default), schema or postgres. */}}
{{- define "hive-metastore.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "hive-metastore.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "hive-metastore.selectorLabels" -}}
app.kubernetes.io/name: hive-metastore
app.kubernetes.io/component: {{ .component | default "metastore" }}
{{- end }}

{{- define "hive-metastore.image" -}}
{{ required "image.repository is required" .Values.image.repository }}:{{ required "image.tag is required" .Values.image.tag }}
{{- end }}

{{/* The address clients connect to. */}}
{{- define "hive-metastore.uri" -}}
thrift://{{ include "hive-metastore.name" . }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.port }}
{{- end }}

{{- define "hive-metastore.property" -}}
<property>
  <name>{{ .name }}</name>
  <value>{{ .value | replace "&" "&amp;" | replace "<" "&lt;" | replace ">" "&gt;" }}</value>
</property>
{{- end }}

{{- define "hive-metastore.metastoreSite" -}}
{{- $props := dict
  "javax.jdo.option.ConnectionURL" (include "hive-metastore.db.url" .)
  "javax.jdo.option.ConnectionDriverName" (include "hive-metastore.db.driver" .)
  "javax.jdo.option.ConnectionUserName" (include "hive-metastore.db.user" .)
  "metastore.warehouse.dir" (required "warehouseDir is required" .Values.warehouseDir)
  "metastore.thrift.port" (toString .Values.port)
  "metastore.housekeeping.leader.election" "lock"
-}}
{{- $auth := include "hive-metastore.authType" . }}
{{- $_ := set $props "metastore.authentication" $auth }}
{{- if eq $auth "KERBEROS" }}
{{- $_ := set $props "metastore.sasl.enabled" "true" }}
{{- $_ := set $props "metastore.kerberos.principal" .Values.auth.kerberos.principal }}
{{- $_ := set $props "metastore.kerberos.keytab.file" "/etc/security/keytabs/hive.keytab" }}
{{- else if eq $auth "LDAP" }}
{{- $_ := set $props "metastore.authentication.ldap.url" (required "auth.ldap.url is required with auth.type LDAP" .Values.auth.ldap.url) }}
{{- with .Values.auth.ldap.baseDN }}{{ $_ := set $props "metastore.authentication.ldap.baseDN" . }}{{ end }}
{{- with .Values.auth.ldap.userDNPattern }}{{ $_ := set $props "metastore.authentication.ldap.userDNPattern" . }}{{ end }}
{{- with .Values.auth.ldap.bindDN }}{{ $_ := set $props "metastore.authentication.ldap.binddn" . }}{{ end }}
{{- else if eq $auth "CONFIG" }}
{{- $_ := set $props "metastore.authentication.config.username" (required "auth.config.username is required with auth.type CONFIG" .Values.auth.config.username) }}
{{- else if eq $auth "CUSTOM" }}
{{- $_ := set $props "metastore.custom.authentication.class" (required "auth.custom.className is required with auth.type CUSTOM" .Values.auth.custom.className) }}
{{- end }}
{{- if include "hive-metastore.authPlain" . }}
{{- /* The server refuses to start with password based authentication and setugi on, its default. */}}
{{- $_ := set $props "metastore.execute.setugi" "false" }}
{{- end }}
{{- $props = merge (deepCopy .Values.metastoreSite) $props }}
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
{{- range $name := keys $props | sortAlpha }}
{{ include "hive-metastore.property" (dict "name" $name "value" (get $props $name | toString)) | indent 2 }}
{{- end }}
</configuration>
{{- end }}

{{- define "hive-metastore.coreSite" -}}
{{- $props := deepCopy .Values.coreSite }}
{{- if eq (include "hive-metastore.authType" .) "KERBEROS" }}
{{- $_ := set $props "hadoop.security.authentication" (get $props "hadoop.security.authentication" | default "kerberos") }}
{{- end }}
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
{{- range $name := keys $props | sortAlpha }}
{{ include "hive-metastore.property" (dict "name" $name "value" (get $props $name | toString)) | indent 2 }}
{{- end }}
</configuration>
{{- end }}

{{- define "hive-metastore.hasCoreSite" -}}
{{- if or .Values.coreSite (eq (include "hive-metastore.authType" .) "KERBEROS") }}true{{ end }}
{{- end }}

{{/* The configuration files, as the data of the configuration Secret. */}}
{{- define "hive-metastore.configData" -}}
metastore-site.xml: |
{{ include "hive-metastore.metastoreSite" . | trim | indent 2 }}
{{- if include "hive-metastore.hasCoreSite" . }}
core-site.xml: |
{{ include "hive-metastore.coreSite" . | trim | indent 2 }}
{{- end }}
{{- end }}

{{/*
The metastore database: the chart's own PostgreSQL when postgres.enabled, else the external one
the database values name.
*/}}
{{- define "hive-metastore.db.type" -}}
{{- if .Values.postgres.enabled }}postgres{{ else }}{{ .Values.database.type }}{{ end }}
{{- end }}

{{- define "hive-metastore.db.url" -}}
{{- if .Values.postgres.enabled -}}
jdbc:postgresql://{{ include "hive-metastore.postgresName" . }}.{{ .Release.Namespace }}.svc.cluster.local:5432/{{ .Values.postgres.database }}
{{- else -}}
{{ required "database.url is required, or set postgres.enabled" .Values.database.url }}
{{- end }}
{{- end }}

{{- define "hive-metastore.db.driver" -}}
{{- if .Values.postgres.enabled }}org.postgresql.Driver{{ else }}{{ required "database.driver is required" .Values.database.driver }}{{ end }}
{{- end }}

{{- define "hive-metastore.db.user" -}}
{{- if .Values.postgres.enabled }}{{ .Values.postgres.user }}{{ else }}{{ required "database.user is required" .Values.database.user }}{{ end }}
{{- end }}

{{- define "hive-metastore.db.secretName" -}}
{{- if .Values.postgres.enabled }}{{ .Values.postgres.existingSecret | default (include "hive-metastore.postgresName" .) }}
{{- else }}{{ required "database.passwordSecret.name is required" .Values.database.passwordSecret.name }}{{ end }}
{{- end }}

{{- define "hive-metastore.db.secretKey" -}}
{{- if .Values.postgres.enabled }}{{ .Values.postgres.existingSecretKey | default "password" }}{{ else }}{{ .Values.database.passwordSecret.key }}{{ end }}
{{- end }}

{{- define "hive-metastore.authType" -}}
{{- $type := upper .Values.auth.type }}
{{- if not (has $type (list "NOSASL" "KERBEROS" "LDAP" "CONFIG" "CUSTOM")) }}
{{- fail (printf "auth.type %q is not one of NOSASL, KERBEROS, LDAP, CONFIG, CUSTOM" .Values.auth.type) }}
{{- end }}
{{- $type }}
{{- end }}

{{/* Whether clients authenticate with a user and password (SASL PLAIN). */}}
{{- define "hive-metastore.authPlain" -}}
{{- if has (include "hive-metastore.authType" .) (list "LDAP" "CONFIG" "CUSTOM") }}true{{ end }}
{{- end }}

{{/*
Secrets of the authentication, as environment variables of the server, passed to it as system
properties by SERVICE_OPTS, read from the Secrets the values name.
*/}}
{{- define "hive-metastore.authEnv" -}}
{{- $auth := include "hive-metastore.authType" . }}
{{- if and (eq $auth "LDAP") .Values.auth.ldap.bindDN }}
- name: LDAP_BIND_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ required "auth.ldap.bindPasswordSecret.name is required with auth.ldap.bindDN" .Values.auth.ldap.bindPasswordSecret.name }}
      key: {{ .Values.auth.ldap.bindPasswordSecret.key }}
{{- else if eq $auth "CONFIG" }}
- name: AUTH_CONFIG_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ required "auth.config.passwordSecret.name is required with auth.type CONFIG" .Values.auth.config.passwordSecret.name }}
      key: {{ .Values.auth.config.passwordSecret.key }}
{{- end }}
{{- end }}

{{- define "hive-metastore.authJavaOpts" -}}
{{- $auth := include "hive-metastore.authType" . }}
{{- if eq $auth "KERBEROS" }} -Djava.security.krb5.conf=/etc/krb5.conf
{{- else if and (eq $auth "LDAP") .Values.auth.ldap.bindDN }} -Dmetastore.authentication.ldap.bindpw=$(LDAP_BIND_PASSWORD)
{{- else if eq $auth "CONFIG" }} -Dmetastore.authentication.config.password=$(AUTH_CONFIG_PASSWORD)
{{- end }}
{{- end }}

{{- define "hive-metastore.passwordEnv" -}}
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "hive-metastore.db.secretName" . }}
      key: {{ include "hive-metastore.db.secretKey" . }}
{{- end }}

{{/*
Shell steps before schematool, the ones the image entrypoint takes before the server: the extra jars
and the mounted configuration.
*/}}
{{- define "hive-metastore.schematoolSetup" -}}
if ls /tmp/ext-jars/*.jar >/dev/null 2>&1; then cp -f /tmp/ext-jars/*.jar "$HIVE_HOME/lib/"; fi
export HIVE_CONF_DIR="$HIVE_HOME/conf"
find /etc/hive/conf-custom -type f -exec ln -sfn {} "$HIVE_CONF_DIR"/ \;
export HADOOP_CONF_DIR="$HIVE_CONF_DIR"
export HADOOP_CLIENT_OPTS="-Xmx{{ .Values.heap }}"
{{- end }}

{{- define "hive-metastore.schematool" -}}
"$HIVE_HOME/bin/schematool" -dbType {{ include "hive-metastore.db.type" . }} -passWord "$DB_PASSWORD"
{{- end }}
