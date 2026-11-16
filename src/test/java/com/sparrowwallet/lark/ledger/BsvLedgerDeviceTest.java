/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bsv.*;
import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class BsvLedgerDeviceTest {
    static class Fake extends AbstractTransport {
        final List<APDUCommand> commands = new ArrayList<>();
        final int fixture;
        final Queue<Integer> signingIndexes = new ArrayDeque<>(List.of(0, 1));
        byte[] messageSignature;
        boolean rejectReview, badSignature;
        Fake(int fixture) { this.fixture = fixture; }
        public void open() {}
        public void close() {}
        public int send(byte[] data) { throw new UnsupportedOperationException(); }
        public Response recv() { throw new UnsupportedOperationException(); }
        public Response exchange(byte[] data) { throw new UnsupportedOperationException(); }
        @Override public Response apduExchange(APDUCommand command) throws DeviceException {
            commands.add(command);
            if(command.getINS() == 0x40) {
                byte[] path = command.getData();
                DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(Utils.hexToBytes("000102030405060708090a0b0c0d0e0f"));
                ByteBuffer buffer = ByteBuffer.wrap(path, 1, path.length - 1);
                for(int i = 0; i < (path[0] & 0xff); i++) key = HDKeyDerivation.deriveChildKey(key, new ChildNumber(buffer.getInt()));
                byte[] pub = key.getPubKey(false);
                byte[] address = ScriptType.P2PKH.getAddress(key.getPubKeyHash()).toString().getBytes(StandardCharsets.US_ASCII);
                return new Response(0x9000, ByteBuffer.allocate(2 + pub.length + address.length + 32).put((byte)pub.length).put(pub).put((byte)address.length).put(address).put(key.getChainCode()).array());
            }
            if(command.getINS() == 0x4e) return new Response(0x9000, command.getP1() == 0x80 ? messageSignature : new byte[]{0, 0});
            if(command.getINS() == 0x42) return new Response(0x9000, new byte[56]);
            if(command.getINS() == 0x4a) {
                if(rejectReview) throw new LedgerTransportException(new Response(0x6985, new byte[0]));
                return new Response(0x9000, new byte[]{0, 0});
            }
            if(command.getINS() == 0x48) {
                byte[] signature = Utils.hexToBytes(BsvFixtures.signature(fixture, signingIndexes.remove(), 0x41).signature());
                if(badSignature) signature[signature.length - 3] ^= 1;
                return new Response(0x9000, signature);
            }
            return new Response(0x9000, new byte[0]);
        }
    }

    BsvLedgerDevice device(Fake fake) throws DeviceException {
        return new BsvLedgerDevice(fake, new LedgerDevice.LedgerVersion("Bitcoin Cash", new Version("2.4.14"), new byte[0]), LedgerModel.LEDGER_NANO_S_PLUS);
    }

    @Test void trustedParentsPartialAndMultisigUseExplicitForkIdAndFullVersion() throws Exception {
        for(int fixture = 0; fixture < 2; fixture++) {
            var request = BsvFixtures.request(fixture);
            byte[] before = BsvSigningCodec.encodeRequest(request);
            Fake fake = new Fake(fixture);
            var result = device(fake).sign(request, BsvFixtures.account(), BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED);
            assertTrue(request.apply(result).isComplete());
            assertArrayEquals(before, BsvSigningCodec.encodeRequest(request));
            var first = fake.commands.stream().filter(c -> c.getINS() == 0x44).findFirst().orElseThrow();
            assertEquals(2, first.getP2());
            assertArrayEquals(Utils.hexToBytes("0403020102"), first.getData());
            for(var command : fake.commands) if(command.getINS() == 0x48) assertEquals(0x41, command.getData()[command.getData().length - 1]);
            assertTrue(fake.commands.stream().anyMatch(c -> c.getINS() == 0x42));
            assertFalse(fake.commands.stream().anyMatch(c -> c.getINS() == 0x46));
        }
    }

    @Test void rejectionNeverFallsBackAndOriginalStaysUnsigned() throws Exception {
        var request = BsvFixtures.request(0); byte[] before = BsvSigningCodec.encodeRequest(request);
        Fake fake = new Fake(0); fake.rejectReview = true;
        assertThrows(DeviceException.class, () -> device(fake).sign(request, BsvFixtures.account(), BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED));
        assertFalse(fake.commands.stream().anyMatch(c -> c.getINS() == 0x46 || c.getINS() == 0x48));
        assertArrayEquals(before, BsvSigningCodec.encodeRequest(request));
    }

    @Test void invalidReturnedSignatureIsRejectedAtomically() throws Exception {
        var request = BsvFixtures.request(0); Fake fake = new Fake(0); fake.badSignature = true;
        assertThrows(DeviceException.class, () -> device(fake).sign(request, BsvFixtures.account(), BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED));
        assertTrue(request.signatures().isEmpty());
    }

    @Test void reducedVerificationRequiresExplicitChoiceAndCorrectWireEncoding() throws Exception {
        var original = BsvFixtures.request(0);
        var inputs = original.inputs().stream().map(i -> new BsvSigningRequest.Input(i.value(), i.lockingScript(), i.signingScript(), i.publicKeys(), null)).toList();
        var request = new BsvSigningRequest(original.transaction(), inputs, original.targets(), List.of());
        Fake fake = new Fake(0);
        assertThrows(DeviceException.class, () -> device(fake).sign(request, BsvFixtures.account(), BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED));
        assertTrue(fake.commands.isEmpty());
        assertTrue(request.apply(device(fake).sign(request, BsvFixtures.account(), BsvSigningRequest.VerificationPolicy.ALLOW_UNVERIFIED)).isComplete());
        var input = fake.commands.stream().filter(c -> c.getINS() == 0x44 && c.getP1() == 0x80).findFirst().orElseThrow().getData();
        assertEquals(2, input[0]); assertEquals(46, input.length);
        assertArrayEquals(request.transaction().getInputs().getFirst().getOutpoint().bitcoinSerialize(), Arrays.copyOfRange(input, 1, 37));
        assertFalse(fake.commands.stream().anyMatch(c -> c.getINS() == 0x42));
    }

    @Test void wrongAppUnknownModelAndUnownedKeyAreRejected() throws Exception {
        Fake fake = new Fake(0);
        assertThrows(DeviceException.class, () -> new BsvLedgerDevice(fake, new LedgerDevice.LedgerVersion("Bitcoin", new Version("2.4.14"), new byte[0]), LedgerModel.LEDGER_NANO_S_PLUS));
        assertThrows(DeviceException.class, () -> new BsvLedgerDevice(fake, new LedgerDevice.LedgerVersion("Bitcoin Cash", new Version("2.4.14"), new byte[0]), LedgerModel.LEDGER_FLEX));
        var original = BsvFixtures.request(0);
        var target = original.targets().getFirst();
        var wrong = new BsvSigningRequest.Target(target.slot(), "m/44'/0'/0'/0/99", 0x41);
        var request = new BsvSigningRequest(original.transaction(), original.inputs(), List.of(wrong), List.of());
        assertThrows(DeviceException.class, () -> device(fake).sign(request, BsvFixtures.account(), BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED));
        assertTrue(fake.commands.isEmpty());
    }

    @Test void selectedInputSigningStillReviewsAllOutputsAndPreservesOtherSlots() throws Exception {
        var original = BsvFixtures.request(0);
        var request = new BsvSigningRequest(original.transaction(), original.inputs(), List.of(original.targets().get(1)), List.of(BsvFixtures.signature(0, 0, 0x41)));
        Fake fake = new Fake(0); fake.signingIndexes.clear(); fake.signingIndexes.add(1);
        var result = device(fake).sign(request, BsvFixtures.account(), BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED);
        assertEquals(1, result.signatures().size()); assertEquals(1, result.signatures().getFirst().slot().inputIndex());
        assertTrue(request.apply(result).isComplete());
        assertEquals(BsvFixtures.signature(0, 0, 0x41).signature(), request.apply(result).signatures().get(original.targets().getFirst().slot()));
        assertEquals(1, fake.commands.stream().filter(c -> c.getINS() == 0x48).count());
    }

    @Test void fullAccountXpubMismatchPreventsSigningEvenWhenPublicKeyMatches() throws Exception {
        var account = BsvFixtures.account();
        byte[] changed = ExtendedKey.fromDescriptor(account.xpub()).getExtendedKeyBytes(ExtendedKey.Header.xpub); changed[5] ^= 1;
        var wrong = new BsvAccount(account.path(), Base58.encodeChecked(changed)); Fake fake = new Fake(0);
        assertThrows(DeviceException.class, () -> device(fake).sign(BsvFixtures.request(0), wrong, BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED));
        assertFalse(fake.commands.stream().anyMatch(c -> c.getINS() == 0x48 || c.getINS() == 0x42));
    }

    @Test void addressAndMessageAreVerifiedAgainstTheAccountKey() throws Exception {
        Fake fake = new Fake(0);
        String path = "m/44'/0'/0'/0/0", message = "Goshawk offline test";
        DeterministicKey key = HDKeyDerivation.createMasterPrivateKey(Utils.hexToBytes("000102030405060708090a0b0c0d0e0f"));
        for(ChildNumber child : KeyDerivation.parsePath(path)) key = HDKeyDerivation.deriveChildKey(key, child);
        assertEquals(ScriptType.P2PKH.getAddress(key.getPubKeyHash()).toString(), device(fake).displayAddress(BsvFixtures.account(), path));
        byte[] compact = Base64.getDecoder().decode(key.signMessage(message, ScriptType.P2PKH));
        var signature = new ECDSASignature(new java.math.BigInteger(1, Arrays.copyOfRange(compact, 1, 33)), new java.math.BigInteger(1, Arrays.copyOfRange(compact, 33, 65)));
        fake.messageSignature = signature.encodeToDER(); fake.messageSignature[0] |= (byte)((compact[0] - 31) & 1);
        assertEquals(Base64.getEncoder().encodeToString(compact), device(fake).signMessage(BsvFixtures.account(), path, message));
        assertThrows(DeviceException.class, () -> device(fake).signMessage(BsvFixtures.account(), path, "Changed message"));
    }

    @Test void bitcoinTypedSighashAndRawInputFramingRemainDistinct() throws Exception {
        Fake fake = new Fake(0);
        var app = new com.sparrowwallet.lark.ledger.legacy.Btchip(fake, new LedgerDevice.LedgerVersion("Bitcoin Legacy", new Version("1.6.5"), new byte[0]));
        app.untrustedHashSign("m/44'/0'/0'/0/0", "", 0, SigHash.ALL);
        var sign = fake.commands.getLast(); assertEquals(1, sign.getData()[sign.getData().length - 1]);
        byte[] outpoint = BsvFixtures.request(0).transaction().getInputs().getFirst().getOutpoint().bitcoinSerialize();
        app.startUntrustedTransaction(true, 0, List.of(Map.of("value", outpoint)), new Script(new byte[0]), 2);
        var input = fake.commands.stream().filter(c -> c.getINS() == 0x44 && c.getP1() == 0x80).findFirst().orElseThrow().getData();
        assertEquals(38, input.length); assertEquals(0, input[0]);
        assertArrayEquals(outpoint, Arrays.copyOfRange(input, 1, 37));
    }

    @Test void bitcoinFactoryRejectsBchAndClosesTransportOnFailure() throws Exception {
        boolean[] closed = {false};
        Fake fake = new Fake(0) {
            @Override public Response apduExchange(APDUCommand command) {
                return new Response(0x9000, Utils.hexToBytes("010c426974636f696e204361736806322e342e31340100"));
            }
            @Override public void close() { closed[0] = true; }
        };
        assertThrows(DeviceException.class, () -> LedgerDevice.openBitcoin(fake));
        assertTrue(closed[0]);
    }

    @Test void appIdentityParsingUsesExactLengthsAndChecksMalformedResponses() throws Exception {
        byte[] data = Utils.hexToBytes("010c426974636f696e204361736806322e342e31340100");
        var version = LedgerDevice.parseVersion(data);
        assertEquals("Bitcoin Cash", version.name()); assertTrue(version.isLegacy());
        for(int length = 0; length < data.length - 2; length++) {
            byte[] truncated = Arrays.copyOf(data, length);
            assertThrows(DeviceException.class, () -> LedgerDevice.parseVersion(truncated));
        }
        assertThrows(IllegalArgumentException.class, () -> new APDUCommand(0xe0, 0x44, 0, 0, new byte[256]));
    }
}
