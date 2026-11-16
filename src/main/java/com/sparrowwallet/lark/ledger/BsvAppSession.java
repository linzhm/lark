/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bsv.BsvDeviceInfo;
import java.util.List;
import java.util.function.LongSupplier;

/** Selected-device app transitions. No key operations, installation, PIN entry, or funds. */
public final class BsvAppSession {
    public interface Access {
        List<BsvDeviceInfo> scan() throws DeviceException;
        void switchApp(String path, boolean openBitcoinCash) throws DeviceException;
        void pause() throws InterruptedException;
    }
    private BsvAppSession() {}

    public static BsvDeviceInfo open(BsvDeviceInfo selected, Access access, LongSupplier clock) throws DeviceException {
        BsvDeviceInfo current = find(selected, access.scan());
        if(current == null) throw new DeviceException("Selected Ledger is missing; select it again");
        checkLocked(current);
        if(current.app().equals("Bitcoin Cash")) return current;
        if(current.app().isBlank()) throw new DeviceException("Selected Ledger is unavailable; close other device sessions and retry");
        if(!current.app().equals("BOLOS")) {
            access.switchApp(current.path(), false);
            current = await(selected, "BOLOS", access, clock);
        }
        access.switchApp(current.path(), true);
        return await(selected, "Bitcoin Cash", access, clock);
    }

    private static BsvDeviceInfo await(BsvDeviceInfo selected, String app, Access access, LongSupplier clock) throws DeviceException {
        long deadline = clock.getAsLong() + 30_000_000_000L;
        while(clock.getAsLong() < deadline) {
            BsvDeviceInfo current = find(selected, access.scan());
            if(current != null) {
                checkLocked(current);
                if(current.app().equals(app)) return current;
            }
            try { access.pause(); }
            catch(InterruptedException e) { Thread.currentThread().interrupt(); throw new DeviceException("Ledger app switch cancelled", e); }
        }
        throw new DeviceException("Selected Ledger did not reconnect with the expected app; unlock and select it again");
    }

    static BsvDeviceInfo find(BsvDeviceInfo selected, List<BsvDeviceInfo> candidates) throws DeviceException {
        List<BsvDeviceInfo> matches = candidates.stream().filter(c -> c.identity().equals(selected.identity())).toList();
        if(matches.size() > 1) throw new DeviceException("Ambiguous Ledger identity; select the device again");
        return matches.isEmpty() ? null : matches.getFirst();
    }

    private static void checkLocked(BsvDeviceInfo info) throws DeviceException {
        if(info.state().equals("locked")) throw new DeviceException("Selected Ledger is locked; enter the PIN on the device and retry");
    }
}
