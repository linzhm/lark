/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.bsv;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.*;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class BsvSigningRequestTest {
    @Test void agreesWithBitcoinXForSixModesAndAllScripts() {
        for(int fixture = 0; fixture < 3; fixture++) {
            var request = BsvFixtures.request(fixture);
            for(int input = 0; input < 2; input++) for(int mode : BsvSigningRequest.SIGHASHES) {
                assertEquals(BsvFixtures.vector(fixture).get("hashes").get(input + ":" + String.format("%02x", mode)).asText(), Utils.bytesToHex(request.hash(input, mode).getBytes()));
                request.verify(BsvFixtures.signature(fixture, input, mode));
            }
        }
    }

    @Test void partialSigningPreservesCosignerAndFinalizesInScriptOrder() {
        for(int fixture = 0; fixture < 3; fixture++) {
            var request = BsvFixtures.request(fixture);
            byte[] before = BsvSigningCodec.encodeRequest(request);
            var one = request.apply(new BsvSigningRequest.Result(request.id(), List.of(BsvFixtures.signature(fixture, 1, 0x41))));
            assertFalse(one.isComplete());
            var roundtrip = BsvSigningCodec.decodeRequest(BsvSigningCodec.encodeRequest(one));
            assertEquals(one.signatures(), roundtrip.signatures());
            var complete = roundtrip.apply(new BsvSigningRequest.Result(request.id(), List.of(BsvFixtures.signature(fixture, 0, 0x41))));
            assertTrue(complete.isComplete());
            assertEquals(BsvFixtures.vector(fixture).get("finalTransaction").asText(), Utils.bytesToHex(complete.finalizeTransaction().bitcoinSerialize(false)));
            assertEquals(BsvFixtures.vector(fixture).get("txid").asText(), complete.finalizeTransaction().getTxId().toString());
            assertArrayEquals(before, BsvSigningCodec.encodeRequest(request));
        }
    }

    @Test void rejectsBadOrReplayedResultsWithoutMutation() {
        var request = BsvFixtures.request(0);
        var valid = BsvFixtures.signature(0, 0, 0x41);
        byte[] before = BsvSigningCodec.encodeRequest(request);
        assertThrows(IllegalArgumentException.class, () -> request.apply(new BsvSigningRequest.Result("different", List.of(valid))));
        assertThrows(IllegalArgumentException.class, () -> request.apply(new BsvSigningRequest.Result(request.id(), List.of(valid, valid))));
        assertThrows(IllegalArgumentException.class, () -> request.apply(new BsvSigningRequest.Result(request.id(), List.of(BsvFixtures.signature(0, 0, 0x42)))));
        var wrong = new BsvSigningRequest.Signature(request.targets().get(1).slot(), valid.signature());
        assertThrows(IllegalArgumentException.class, () -> request.apply(new BsvSigningRequest.Result(request.id(), List.of(valid, wrong))));
        var signed = request.apply(new BsvSigningRequest.Result(request.id(), List.of(valid)));
        assertThrows(IllegalArgumentException.class, () -> signed.apply(new BsvSigningRequest.Result(signed.id(), List.of(valid))));
        assertArrayEquals(before, BsvSigningCodec.encodeRequest(request));
    }

    @Test void bindsVersionSequenceLocktimeAndOutputAmounts() {
        var original = BsvFixtures.request(0);
        for(int field = 0; field < 4; field++) {
            Transaction tx = original.transaction();
            switch(field) {
                case 0 -> tx.setVersion(2);
                case 1 -> tx.setLocktime(1);
                case 2 -> tx.getInputs().getFirst().setSequenceNumber(0);
                case 3 -> { byte[] raw = tx.bitcoinSerialize(false); raw[88]--; tx = new Transaction(raw); }
            }
            var changed = new BsvSigningRequest(tx, original.inputs(), original.targets(), List.of());
            assertNotEquals(original.id(), changed.id());
            assertThrows(IllegalArgumentException.class, () -> changed.verify(BsvFixtures.signature(0, 0, 0x41)));
        }
        Transaction detached = original.transaction(); detached.setVersion(99);
        assertEquals(0x01020304L, original.transaction().getVersion());
    }

    @Test void validatesParentsBeforeAnyTrustDowngrade() {
        var original = BsvFixtures.request(0);
        var input = original.inputs().getFirst();
        var bad = new BsvSigningRequest.Input(input.value() + 1, input.lockingScript(), input.signingScript(), input.publicKeys(), input.previousTransaction());
        assertThrows(IllegalArgumentException.class, () -> new BsvSigningRequest(original.transaction(), List.of(bad, original.inputs().get(1)), original.targets(), List.of()));
        var trailing = new BsvSigningRequest.Input(input.value(), input.lockingScript(), input.signingScript(), input.publicKeys(), input.previousTransaction() + "00");
        assertThrows(IllegalArgumentException.class, () -> new BsvSigningRequest(original.transaction(), List.of(trailing, original.inputs().get(1)), original.targets(), List.of()));
    }

    @Test void rejectsWitnessMissingSingleOutputAndInvalidFields() {
        var request = BsvFixtures.request(0);
        var witness = request.transaction(); witness.setSegwitFlag(1);
        assertThrows(IllegalArgumentException.class, () -> new BsvSigningRequest(witness, request.inputs(), request.targets(), List.of()));
        var invalid = request.transaction(); invalid.setVersion(0x1_0000_0000L);
        assertThrows(IllegalArgumentException.class, () -> new BsvSigningRequest(invalid, request.inputs(), request.targets(), List.of()));
        var original = request.transaction();
        var oneOutput = new Transaction();
        oneOutput.setVersion(original.getVersion()); oneOutput.setLocktime(original.getLocktime());
        for(var input : original.getInputs()) { oneOutput.addInput(input.getOutpoint().getHash(), input.getOutpoint().getIndex(), new Script(new byte[0])); }
        oneOutput.addOutput(900, original.getOutputs().getFirst().getScript());
        var limited = new BsvSigningRequest(oneOutput, request.inputs(), List.of(), List.of());
        assertThrows(IllegalArgumentException.class, () -> limited.hash(1, 0x43));
        assertThrows(IllegalArgumentException.class, () -> request.hash(0, 1));
        assertThrows(IllegalStateException.class, request::finalizeTransaction);
    }

    @Test void boundsJsonAndRejectsTamperingUnknownFieldsAndDuplicateKeys() {
        var request = BsvFixtures.request(0);
        String json = new String(BsvSigningCodec.encodeRequest(request), StandardCharsets.UTF_8);
        for(String bad : List.of("null", json.replace("\"BSV\"", "\"BTC\""), json.replace(request.id(), "00"), json + "{}",
                json.replace("\"version\":1", "\"version\":1,\"version\":1"), json.replace("\"version\":1", "\"version\":1,\"unknown\":true"))) {
            assertThrows(IllegalArgumentException.class, () -> BsvSigningCodec.decodeRequest(bad.getBytes(StandardCharsets.UTF_8)));
        }
        assertThrows(IllegalArgumentException.class, () -> BsvSigningCodec.decodeRequest(new byte[BsvSigningCodec.MAX_BYTES + 1]));
    }

    @Test void pairsByCompleteAccountAndPreservesOriginalPath() {
        BsvAccount account = BsvFixtures.account();
        assertEquals(BsvFixtures.request(0).targets().getFirst().slot().publicKey(), Utils.bytesToHex(account.derive("m/44'/0'/0'/0/0").getPubKey()));
        assertThrows(IllegalArgumentException.class, () -> account.derive("m/44'/145'/0'/0/0"));
        assertThrows(IllegalArgumentException.class, () -> new BsvAccount("m/44'/236'/0'", account.xpub()));
        assertThrows(IllegalArgumentException.class, () -> account.derive("m/44'/0'/0'/0/0'"));
    }
}
