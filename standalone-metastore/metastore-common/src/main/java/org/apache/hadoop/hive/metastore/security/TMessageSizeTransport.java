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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.hadoop.hive.metastore.security;

import org.apache.thrift.TConfiguration;
import org.apache.thrift.transport.TEndpointTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;

/**
 * Transport wrapper that enforces maxMessageSize on all bytes read between two flushes.
 *
 * TSaslTransport buffers each incoming frame in a TMemoryInputTransport. Up to Thrift 0.23 its
 * read() charged every read against maxMessageSize and threw once a frame exceeded it. Since
 * 0.24 the charge is made in consumeBuffer() and saturates at 0 without an exception, and 0.25
 * only rejects frames larger than maxFrameSize, so a maxMessageSize below it is not enforced.
 *
 * This wrapper charges every read against its own TEndpointTransport budget and resets it on
 * flush(), like TIOStreamTransport, so each incoming message starts with the full limit.
 */
public class TMessageSizeTransport extends TEndpointTransport {

  private final TTransport wrapped;

  public TMessageSizeTransport(TTransport wrapped) throws TTransportException {
    super(wrapped.getConfiguration() != null ? wrapped.getConfiguration() : new TConfiguration());
    this.wrapped = wrapped;
  }

  public TTransport getWrapped() {
    return wrapped;
  }

  @Override
  public boolean isOpen() {
    return wrapped.isOpen();
  }

  @Override
  public void open() throws TTransportException {
    wrapped.open();
  }

  @Override
  public void close() {
    wrapped.close();
  }

  @Override
  public int read(byte[] buf, int off, int len) throws TTransportException {
    int n = wrapped.read(buf, off, len);
    if (n > 0) {
      countConsumedMessageBytes(n);
    }
    return n;
  }

  @Override
  public int readAll(byte[] buf, int off, int len) throws TTransportException {
    checkReadBytesAvailable(len);
    int got = 0;
    int ret;
    while (got < len) {
      ret = wrapped.read(buf, off + got, len - got);
      if (ret <= 0) {
        throw new TTransportException(
            "Cannot read. Remote side has closed. Tried to read "
                + len + " bytes, but only got " + got + " bytes.");
      }
      got += ret;
    }
    countConsumedMessageBytes(got);
    return got;
  }

  @Override
  public void write(byte[] buf, int off, int len) throws TTransportException {
    wrapped.write(buf, off, len);
  }

  @Override
  public void flush() throws TTransportException {
    wrapped.flush();
    resetConsumedMessageSize(-1);
  }

  @Override
  public byte[] getBuffer() {
    return wrapped.getBuffer();
  }

  @Override
  public int getBufferPosition() {
    return wrapped.getBufferPosition();
  }

  @Override
  public int getBytesRemainingInBuffer() {
    int remaining = wrapped.getBytesRemainingInBuffer();
    return remaining < 0 ? remaining : (int) Math.min(remaining, remainingMessageSize);
  }

  @Override
  public void consumeBuffer(int len) {
    wrapped.consumeBuffer(len);
    if (len > 0) {
      try {
        countConsumedMessageBytes(len);
      } catch (TTransportException e) {
        throw new RuntimeException(e);
      }
    }
  }

  @Override
  public void updateKnownMessageSize(long size) throws TTransportException {
    wrapped.updateKnownMessageSize(size);
    resetConsumedMessageSize(size < 0 ? -1 : size);
  }
}
