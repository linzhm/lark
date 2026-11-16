/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bsv.BsvDeviceInfo;
import org.junit.jupiter.api.Test;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class BsvAppSessionTest {
    BsvDeviceInfo info(String path, String id, String app) { return new BsvDeviceInfo(path, "Nano S Plus", id, "ready", app, "2.4.14", ""); }
    class Access implements BsvAppSession.Access {
        Queue<List<BsvDeviceInfo>> scans = new ArrayDeque<>();
        List<String> switches = new ArrayList<>();
        AtomicLong time = new AtomicLong();
        public List<BsvDeviceInfo> scan() { return scans.size() > 1 ? scans.remove() : scans.isEmpty() ? List.of() : scans.peek(); }
        public void switchApp(String path, boolean open) { switches.add(path + ":" + open); }
        public void pause() throws InterruptedException { time.addAndGet(10_000_000_000L); }
    }
    @Test void reconnectsOnlyTheSelectedIdentityAcrossPathChanges() throws Exception {
        var selected = info("before", "selected", "Bitcoin"); Access access = new Access();
        access.scans.add(List.of(selected));
        access.scans.add(List.of(info("other", "another", "Bitcoin Cash")));
        access.scans.add(List.of(info("dashboard", "selected", "BOLOS")));
        access.scans.add(List.of(info("after", "selected", "Bitcoin Cash")));
        assertEquals("after", BsvAppSession.open(selected, access, access.time::get).path());
        assertEquals(List.of("before:false", "dashboard:true"), access.switches);
    }
    @Test void neverSelectsFirstDeviceAfterDisconnect() {
        var selected = info("before", "selected", "Bitcoin"); Access access = new Access();
        access.scans.add(List.of(selected)); access.scans.add(List.of(info("other", "another", "Bitcoin Cash")));
        assertThrows(DeviceException.class, () -> BsvAppSession.open(selected, access, access.time::get));
        assertEquals(List.of("before:false"), access.switches); assertEquals(30_000_000_000L, access.time.get());
    }
    @Test void ambiguousIdentityRequiresSelectionAgain() {
        var selected = info("a", "same", "Bitcoin"); Access access = new Access();
        access.scans.add(List.of(selected, info("b", "same", "Bitcoin")));
        assertThrows(DeviceException.class, () -> BsvAppSession.open(selected, access, access.time::get));
        assertTrue(access.switches.isEmpty());
    }
    @Test void readyDeviceNeedsNoSwitchAndLockedDeviceNeedsOnDevicePin() throws Exception {
        var ready = info("a", "selected", "Bitcoin Cash"); Access access = new Access(); access.scans.add(List.of(ready));
        assertEquals(ready, BsvAppSession.open(ready, access, access.time::get)); assertTrue(access.switches.isEmpty());
        var locked = new BsvDeviceInfo("a", "Nano S", "selected", "locked", "", "", "");
        access.scans.clear(); access.scans.add(List.of(locked));
        assertThrows(DeviceException.class, () -> BsvAppSession.open(locked, access, access.time::get));
        assertTrue(access.switches.isEmpty());
    }
    @Test void cancellationStopsReconnect() {
        var selected = info("a", "selected", "Bitcoin");
        Access access = new Access() { @Override public void pause() throws InterruptedException { throw new InterruptedException(); } };
        access.scans.add(List.of(selected)); access.scans.add(List.of());
        try { assertThrows(DeviceException.class, () -> BsvAppSession.open(selected, access, access.time::get)); assertTrue(Thread.currentThread().isInterrupted()); }
        finally { Thread.interrupted(); }
    }
}
