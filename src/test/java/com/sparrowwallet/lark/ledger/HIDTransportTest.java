/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.DeviceException;
import org.junit.jupiter.api.Test;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class HIDTransportTest {
    static class Channel implements HIDTransport.Channel {
        final Queue<byte[]> reads = new ArrayDeque<>();
        final AtomicLong clock = new AtomicLong();
        boolean closed;
        public boolean open() { return true; }
        public int write(byte[] packet) { return 64; }
        public int read(byte[] packet, int timeout) {
            clock.addAndGet(timeout * 1_000_000L);
            if(reads.isEmpty()) return 0;
            byte[] next = reads.remove(); System.arraycopy(next, 0, packet, 0, next.length); return next.length;
        }
        public void close() { closed = true; }
        public String error() { return "test"; }
    }
    byte[] frame(int sequence, int length) {
        byte[] bytes = new byte[64]; bytes[0] = 1; bytes[1] = 1; bytes[2] = 5; bytes[4] = (byte)sequence;
        if(sequence == 0) { bytes[5] = (byte)(length >> 8); bytes[6] = (byte)length; }
        return bytes;
    }
    @Test void firstAndContinuationReadsShareABoundedDeadline() throws Exception {
        for(boolean continuation : List.of(false, true)) {
            Channel channel = new Channel();
            if(continuation) channel.reads.add(frame(0, 100));
            HIDTransport transport = new HIDTransport(channel, 250, channel.clock::get);
            assertThrows(DeviceException.class, () -> transport.exchange(new byte[]{0}));
            assertTrue(channel.closed); assertTrue(channel.clock.get() <= 251_000_000L);
        }
    }
    @Test void refusesMalformedLengthAndShortFrames() throws Exception {
        for(byte[] malformed : List.of(frame(0, 1), new byte[]{1,1,5}, frame(1, 2))) {
            Channel channel = new Channel(); channel.reads.add(malformed);
            assertThrows(DeviceException.class, () -> new HIDTransport(channel, 1000, channel.clock::get).exchange(new byte[]{0}));
            assertTrue(channel.closed);
        }
    }
    @Test void returnsExactPayloadAndStatus() throws Exception {
        Channel channel = new Channel(); byte[] frame = frame(0, 3);
        frame[7] = 42; frame[8] = (byte)0x90; channel.reads.add(frame);
        var response = new HIDTransport(channel, 1000, channel.clock::get).exchange(new byte[]{0});
        assertEquals(0x9000, response.sw()); assertArrayEquals(new byte[]{42}, response.data());
    }
    @Test void rejectsConcurrentExchangeWithoutClosingActiveRequest() throws Exception {
        CountDownLatch reading = new CountDownLatch(1), release = new CountDownLatch(1);
        Channel channel = new Channel() {
            @Override public int read(byte[] bytes, int timeout) {
                reading.countDown();
                try { release.await(2, TimeUnit.SECONDS); } catch(InterruptedException e) { Thread.currentThread().interrupt(); }
                return super.read(bytes, timeout);
            }
        };
        byte[] response = frame(0, 2); response[7] = (byte)0x90; channel.reads.add(response);
        HIDTransport transport = new HIDTransport(channel, 1000, channel.clock::get);
        try(ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<?> first = executor.submit(() -> { try { transport.exchange(new byte[]{0}); } catch(DeviceException e) { throw new RuntimeException(e); } });
            assertTrue(reading.await(1, TimeUnit.SECONDS));
            assertThrows(DeviceException.class, () -> transport.exchange(new byte[]{0}));
            assertFalse(channel.closed); release.countDown(); first.get(2, TimeUnit.SECONDS);
        }
    }
}
