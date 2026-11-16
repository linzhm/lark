// Modified for Goshawk BSV integration, 2026-11-16. Existing Lark Apache-2.0 terms retained.
package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.DeviceException;
import org.hid4java.HidDevice;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

public class HIDTransport extends AbstractTransport {
    interface Channel {
        boolean open();
        int write(byte[] packet);
        int read(byte[] packet, int timeoutMs);
        void close();
        String error();
    }
    private final Channel channel;
    private final int timeoutMs;
    private final LongSupplier clock;
    private final ReentrantLock exchangeLock = new ReentrantLock();

    public HIDTransport(HidDevice device) { this(device, 120_000); }

    public HIDTransport(HidDevice device, int timeoutMs) {
        this(new Channel() {
            public boolean open() { return !device.isClosed() || device.open(); }
            public int write(byte[] packet) { return device.write(packet, 64, (byte)0); }
            public int read(byte[] packet, int timeout) { return device.read(packet, timeout); }
            public void close() { device.close(); }
            public String error() { return device.getLastErrorMessage(); }
        }, timeoutMs, System::nanoTime);
    }

    HIDTransport(Channel channel, int timeoutMs, LongSupplier clock) {
        if(timeoutMs <= 0) throw new IllegalArgumentException("Positive response timeout required");
        this.channel = channel;
        this.timeoutMs = timeoutMs;
        this.clock = clock;
        open();
    }

    @Override
    public void open() {
        if(!channel.open()) {
            channel.close();
            throw new IllegalStateException("Cannot open Ledger. Close Ledger Wallet or other device sessions, then retry. " + channel.error());
        }
    }

    @Override
    public int send(byte[] data) throws DeviceException {
        if(data == null || data.length > 65535) throw new IllegalArgumentException("Invalid Ledger APDU length");
        byte[] framed = ByteBuffer.allocate(2 + data.length).putShort((short)data.length).put(data).array();
        int sequence = 0;
        for(int offset = 0; offset < framed.length; offset += 59) {
            byte[] packet = new byte[64];
            packet[0] = 1; packet[1] = 1; packet[2] = 5;
            packet[3] = (byte)(sequence >> 8); packet[4] = (byte)sequence++;
            System.arraycopy(framed, offset, packet, 5, Math.min(59, framed.length - offset));
            if(channel.write(packet) < 64) throw new DeviceException("Cannot write complete Ledger packet. Close other device sessions and retry. " + channel.error());
        }
        return data.length;
    }

    @Override
    public Response recv() throws DeviceException {
        long deadline = clock.getAsLong() + timeoutMs * 1_000_000L;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int sequence = 0, length = -1;
        while(length < 0 || bytes.size() < length) {
            if(Thread.currentThread().isInterrupted()) throw new DeviceException("Ledger operation cancelled; finish or reject any pending request on the device");
            long remaining = deadline - clock.getAsLong();
            if(remaining <= 0) throw new DeviceException("Ledger response timed out. Finish or reject the request on the device, reconnect and retry");
            byte[] packet = new byte[64];
            int read = channel.read(packet, (int)Math.max(1, Math.min(100, remaining / 1_000_000)));
            if(read < 0) throw new DeviceException("Ledger disconnected or unavailable. " + channel.error());
            if(read == 0) continue;
            int header = sequence == 0 ? 7 : 5;
            if(read < header || read > 64 || packet[0] != 1 || packet[1] != 1 || packet[2] != 5 ||
                    (packet[3] & 0xff) != sequence >> 8 || (packet[4] & 0xff) != (sequence & 0xff)) {
                throw new DeviceException("Invalid Ledger response framing/sequence");
            }
            if(sequence == 0) {
                length = ((packet[5] & 0xff) << 8) | (packet[6] & 0xff);
                if(length < 2) throw new DeviceException("Ledger response has no status word");
            }
            int payload = Math.min(64 - header, length - bytes.size());
            if(read < header + payload) throw new DeviceException("Truncated Ledger response packet");
            bytes.write(packet, header, payload);
            sequence++;
        }
        byte[] response = bytes.toByteArray();
        int status = ((response[length - 2] & 0xff) << 8) | (response[length - 1] & 0xff);
        return new Response(status, Arrays.copyOf(response, length - 2));
    }

    @Override
    public Response exchange(byte[] data) throws DeviceException {
        if(!exchangeLock.tryLock()) throw new DeviceException("Ledger is busy with another operation");
        try {
            send(data);
            return recv();
        } catch(DeviceException | RuntimeException e) {
            channel.close();
            throw e;
        } finally { exchangeLock.unlock(); }
    }

    @Override
    public void close() throws IOException { channel.close(); }
}
