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

package org.apache.hadoop.hive.common.auth;

import java.net.ServerSocket;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.AuthorizeCallback;

import org.apache.thrift.TConfiguration;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.junit.Assert;
import org.junit.Test;

public class TestHiveAuthUtils {

  private static final CallbackHandler CALLBACKS = callbacks -> {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback) {
        ((NameCallback) callback).setName("user");
      } else if (callback instanceof PasswordCallback) {
        ((PasswordCallback) callback).setPassword("password".toCharArray());
      } else if (callback instanceof AuthorizeCallback) {
        ((AuthorizeCallback) callback).setAuthorized(true);
      }
    }
  };

  @Test
  public void testFrameSizeFollowsMessageSize() throws Exception {
    TSocket socket = new TSocket("localhost", 0);

    HiveAuthUtils.configureThriftMaxMessageSize(socket, 200 * 1024 * 1024);

    Assert.assertEquals(200 * 1024 * 1024, socket.getConfiguration().getMaxMessageSize());
    Assert.assertEquals(200 * 1024 * 1024, socket.getConfiguration().getMaxFrameSize());
  }

  @Test
  public void testSmallMessageSizeKeepsDefaultFrameSize() throws Exception {
    TSocket socket = new TSocket("localhost", 0);

    HiveAuthUtils.configureThriftMaxMessageSize(socket, 1024);

    Assert.assertEquals(1024, socket.getConfiguration().getMaxMessageSize());
    Assert.assertEquals(TConfiguration.DEFAULT_MAX_FRAME_SIZE, socket.getConfiguration().getMaxFrameSize());
  }

  @Test
  public void testSaslResponseLargerThanDefaultFrameSize() throws Exception {
    String value = "x".repeat(TConfiguration.DEFAULT_MAX_FRAME_SIZE + 1024);
    try (ServerSocket serverSocket = new ServerSocket(0)) {
      CompletableFuture<Void> server = CompletableFuture.runAsync(() -> {
        try {
          TSocket socket = HiveAuthUtils.configureThriftMaxMessageSize(new TSocket(serverSocket.accept()), -1);
          TTransport transport = new TSaslServerTransport("CRAM-MD5", "hive", "localhost", new HashMap<>(),
              CALLBACKS, socket);
          transport.open();
          new TBinaryProtocol(transport).writeString(value);
          transport.flush();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      });

      TTransport socket = HiveAuthUtils.getSocketTransport("localhost", serverSocket.getLocalPort(), 30000);
      TTransport transport = new TSaslClientTransport("CRAM-MD5", null, "hive", "localhost", new HashMap<>(),
          CALLBACKS, socket);
      transport.open();
      try {
        Assert.assertEquals(value.length(), new TBinaryProtocol(transport).readString().length());
      } finally {
        transport.close();
      }
      server.get(30, TimeUnit.SECONDS);
    }
  }
}
