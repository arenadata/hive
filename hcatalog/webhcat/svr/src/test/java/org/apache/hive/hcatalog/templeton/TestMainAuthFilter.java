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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.hive.hcatalog.templeton;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import org.eclipse.jetty.servlet.FilterHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TestMainAuthFilter {
  private String originalRealm;
  private String originalKdc;

  @Before
  public void configureTestRealm() {
    originalRealm = System.getProperty("java.security.krb5.realm");
    originalKdc = System.getProperty("java.security.krb5.kdc");
    System.setProperty("java.security.krb5.realm", "EXAMPLE.COM");
    System.setProperty("java.security.krb5.kdc", "localhost");
  }

  private void restoreProperty(String key, String value) {
    if (value == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, value);
    }
  }

  @After
  public void restoreSimpleAuthentication() {
    UserGroupInformation.setConfiguration(new Configuration(false));
    restoreProperty("java.security.krb5.realm", originalRealm);
    restoreProperty("java.security.krb5.kdc", originalKdc);
  }

  @Test
  public void testSimpleAuthenticationConfiguration() {
    UserGroupInformation.setConfiguration(new Configuration(false));
    Main main = new Main(new String[] {"-D" + AppConfig.UNIT_TEST_MODE + "=true"});
    FilterHolder filter = main.makeAuthFilter();
    assertEquals(AuthenticationFilter.class, filter.getHeldClass());
    assertEquals("dfs.web.authentication", filter.getInitParameter(AuthenticationFilter.CONFIG_PREFIX));
    assertEquals("/", filter.getInitParameter("dfs.web.authentication.cookie.path"));
    assertEquals("simple", filter.getInitParameter("dfs.web.authentication.type"));
    assertEquals("true", filter.getInitParameter("dfs.web.authentication.simple.anonymous.allowed"));
  }

  @Test
  public void testKerberosAuthenticationConfiguration() {
    Configuration conf = new Configuration(false);
    conf.set("hadoop.security.authentication", "kerberos");
    UserGroupInformation.setConfiguration(conf);
    Main main = new Main(new String[] {"-D" + AppConfig.UNIT_TEST_MODE + "=true",
        "-D" + AppConfig.KERBEROS_PRINCIPAL + "=HTTP/localhost@EXAMPLE.COM",
        "-D" + AppConfig.KERBEROS_KEYTAB + "=/test-only/webhcat.keytab",
        "-D" + AppConfig.KERBEROS_SECRET + "=test-only-signature"});
    FilterHolder filter = main.makeAuthFilter();
    assertEquals(AuthenticationFilter.class, filter.getHeldClass());
    assertEquals("dfs.web.authentication", filter.getInitParameter(AuthenticationFilter.CONFIG_PREFIX));
    assertEquals("/", filter.getInitParameter("dfs.web.authentication.cookie.path"));
    assertEquals("kerberos", filter.getInitParameter("dfs.web.authentication.type"));
    assertEquals("HTTP/localhost@EXAMPLE.COM",
        filter.getInitParameter("dfs.web.authentication.kerberos.principal"));
    assertEquals("/test-only/webhcat.keytab",
        filter.getInitParameter("dfs.web.authentication.kerberos.keytab"));
    assertEquals("test-only-signature",
        filter.getInitParameter("dfs.web.authentication.signature.secret"));
  }
  @Test
  public void testWebHCatProxyPolicyAllowsConfiguredUser() throws Exception {
    AppConfig conf = new AppConfig();
    conf.set("webhcat.proxyuser.adh9961-allowed-proxy.hosts", "*");
    conf.set("webhcat.proxyuser.adh9961-allowed-proxy.groups", "*");
    ProxyUserSupport.processProxyuserConfig(conf);
    ProxyUserSupport.validate("adh9961-allowed-proxy", "127.0.0.1", "target-user");
  }

  @Test(expected = NotAuthorizedException.class)
  public void testWebHCatProxyPolicyRejectsDisallowedGroup() throws Exception {
    AppConfig conf = new AppConfig();
    conf.set("webhcat.proxyuser.adh9961-denied-proxy.hosts", "*");
    conf.set("webhcat.proxyuser.adh9961-denied-proxy.groups", "");
    ProxyUserSupport.processProxyuserConfig(conf);
    ProxyUserSupport.validate("adh9961-denied-proxy", "127.0.0.1", "target-user");
  }

}
