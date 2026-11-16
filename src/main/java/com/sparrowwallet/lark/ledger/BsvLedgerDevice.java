/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bsv.*;
import com.sparrowwallet.lark.ledger.legacy.Btchip;

import java.nio.charset.StandardCharsets;
import java.util.*;
import com.sparrowwallet.lark.bsv.BsvSigningRequest.VerificationPolicy;
import com.sparrowwallet.lark.bsv.BsvSigningRequest.VerificationPlan;

/** BCH/BSV route over Lark's existing legacy protocol; never a modern Bitcoin PSBT client. */
public final class BsvLedgerDevice extends LegacyLedgerDevice {
    private final Btchip app;
    private final LedgerVersion version;
    private final boolean modern;

    public BsvLedgerDevice(Transport transport, LedgerVersion version, LedgerModel model) throws DeviceException {
        super(transport, version);
        if(!version.name().equals("Bitcoin Cash")) throw new DeviceException("Open Bitcoin Cash on the selected Ledger");
        if(version.version().compareTo(new Version("1.1.8")) < 0) throw new DeviceException("BCH app is outside the supported protocol");
        modern = model == LedgerModel.LEDGER_NANO_X || model == LedgerModel.LEGACY_LEDGER_NANO_X || model == LedgerModel.LEDGER_NANO_S_PLUS;
        if(!modern && model != LedgerModel.LEDGER_NANO_S && model != LedgerModel.LEGACY_LEDGER_NANO_S) throw new DeviceException("No BSV capability evidence for this Ledger model");
        this.app = new Btchip(transport, version);
        this.version = version;
    }

    public BsvAccount readAccount(String path) throws DeviceException {
        requireMainnet();
        // Validate the requested path before issuing a key derivation command.
        var nodes = KeyDerivation.parsePath(path);
        if(nodes.size() != 3 || nodes.stream().anyMatch(n -> !n.isHardened()) || nodes.getFirst().num() != 44 ||
                (nodes.get(1).num() != 0 && nodes.get(1).num() != 145)) throw new DeviceException("Unsupported BCH account path");
        return new BsvAccount(path, super.getExtendedPubkey(path, false).getExtendedKey(ExtendedKey.Header.xpub));
    }

    public void pair(BsvAccount account) throws DeviceException {
        if(!readAccount(account.path()).equals(account)) throw new DeviceException("Selected Ledger account xpub does not match this wallet");
    }

    public String displayAddress(BsvAccount account, String path) throws DeviceException {
        ECKey expected = account.derive(path);
        pair(account);
        Map<String, byte[]> response = app.getWalletPublicKey(path, true);
        String address = new String(response.get("address"), StandardCharsets.US_ASCII);
        if(!Arrays.equals(expected.getPubKey(), ECKey.fromPublicOnly(response.get("publicKey")).getPubKey(true)) ||
                !address.equals(ScriptType.P2PKH.getAddress(expected.getPubKeyHash()).toString())) throw new DeviceException("Ledger address/public key does not match the selected account");
        return address;
    }

    public String signMessage(BsvAccount account, String path, String message) throws DeviceException {
        ECKey expected = account.derive(path);
        if(message.isEmpty() || message.getBytes(StandardCharsets.UTF_8).length > 65535) throw new DeviceException("Message must contain 1 to 65535 UTF-8 bytes");
        pair(account);
        String signature = super.signMessage(message, path);
        try {
            if(!Arrays.equals(expected.getPubKey(), ECKey.signedMessageToKey(message, signature, false).getPubKey(true))) throw new DeviceException("Invalid Ledger message signature");
        } catch(java.security.SignatureException e) {
            throw new DeviceException("Invalid Ledger message signature", e);
        }
        return signature;
    }

    public VerificationPlan plan(BsvSigningRequest request) throws DeviceException {
        Transaction tx = request.transaction();
        if(tx.getInputs().size() > 256 || tx.getOutputs().size() > 256) throw new DeviceException("Transaction exceeds host operation budget");
        for(TransactionOutput output : tx.getOutputs()) {
            if(!ScriptType.P2PKH.isScriptType(output.getScript())) throw new DeviceException("This BSV adapter currently reviews P2PKH outputs only");
        }
        for(BsvSigningRequest.Input input : request.inputs()) {
            if(input.script().getProgram().length > 8192) throw new DeviceException("Signing script exceeds host operation budget");
        }
        if(version.version().compareTo(new Version("1.4.0")) < 0) return new VerificationPlan(false, "App predates the trusted-input route");
        if(tx.getInputs().size() > (modern ? 16 : 4) || tx.getOutputs().size() > (modern ? 32 : 8)) return new VerificationPlan(false, "Input/output count exceeds trusted verification budget");
        long totalBytes = 0, commands = 0;
        for(BsvSigningRequest.Input input : request.inputs()) {
            if(input.previousTransaction() == null) return new VerificationPlan(false, "Complete previous transaction is missing");
            byte[] raw = Utils.hexToBytes(input.previousTransaction());
            totalBytes += raw.length;
            if(raw.length > (modern ? 131072 : 32768) || totalBytes > (modern ? 262144 : 65536)) return new VerificationPlan(false, "Previous transactions exceed trusted byte budget");
            Transaction parent = new Transaction(raw); // Already bound to the outpoint, amount and script by the request.
            commands += 3;
            for(TransactionInput in : parent.getInputs()) {
                if(in.getScriptBytes().length > (modern ? 32768 : 8192)) return new VerificationPlan(false, "Previous script exceeds trusted script budget");
                commands += 1 + Math.max(1, (in.getScriptBytes().length + 250) / 251);
            }
            for(TransactionOutput out : parent.getOutputs()) {
                if(out.getScriptBytes().length > (modern ? 32768 : 8192)) return new VerificationPlan(false, "Previous script exceeds trusted script budget");
                commands += 1 + (out.getScriptBytes().length + 254) / 255;
            }
            if(commands > (modern ? 2048 : 512)) return new VerificationPlan(false, "Previous transactions exceed trusted communication budget");
        }
        return new VerificationPlan(true, "Parents checked; chain membership, unspentness and coinbase maturity remain wallet responsibilities");
    }

    public BsvSigningRequest.Result sign(BsvSigningRequest request, BsvAccount account, VerificationPolicy policy) throws DeviceException {
        Objects.requireNonNull(policy);
        VerificationPlan verification = plan(request);
        if(!verification.trusted() && policy != VerificationPolicy.ALLOW_UNVERIFIED) throw new DeviceException(verification.reason() + "; explicit reduced-verification consent is required");
        List<BsvSigningRequest.Target> targets = request.targets().stream().filter(t -> !request.signatures().containsKey(t.slot())).toList();
        for(BsvSigningRequest.Target target : targets) {
            if(target.sighash() != 0x41) throw new DeviceException("Ledger BCH only supports BSV SIGHASH_ALL | FORKID (0x41)");
            if(!Utils.bytesToHex(account.derive(target.path()).getPubKey()).equals(target.slot().publicKey())) throw new DeviceException("Signing key/path does not belong to the selected account");
        }
        if(targets.isEmpty()) return new BsvSigningRequest.Result(request.id(), List.of());
        pair(account);
        Transaction tx = request.transaction();
        List<Map<String, Object>> chipInputs = new ArrayList<>();
        for(int i = 0; i < request.inputs().size(); i++) {
            BsvSigningRequest.Input input = request.inputs().get(i);
            TransactionInput txin = tx.getInputs().get(i);
            Map<String, Object> chipInput;
            if(verification.trusted()) {
                chipInput = app.getTrustedInput(new Transaction(Utils.hexToBytes(input.previousTransaction())), txin.getOutpoint().getIndex());
            } else {
                byte[] amount = new byte[8]; Utils.int64ToByteArrayLE(input.value(), amount, 0);
                chipInput = new HashMap<>();
                chipInput.put("value", Utils.concat(txin.getOutpoint().bitcoinSerialize(), amount));
            }
            byte[] sequence = new byte[4]; Utils.uint32ToByteArrayLE(txin.getSequenceNumber(), sequence, 0);
            chipInput.put("sequence", Utils.bytesToHex(sequence));
            // Legacy protocol flag selects the ForkID preimage path, not witness transaction serialization.
            chipInput.put("witness", Boolean.TRUE);
            chipInputs.add(chipInput);
        }
        app.startUntrustedTransaction(true, 0, chipInputs, request.inputs().getFirst().script(), tx.getVersion());
        app.finalizeBsvOutputs(tx); // Review every output; no hidden change or legacy fallback.
        List<BsvSigningRequest.Signature> signatures = new ArrayList<>();
        for(BsvSigningRequest.Target target : targets) {
            int index = target.slot().inputIndex();
            app.startUntrustedTransaction(false, 0, List.of(chipInputs.get(index)), request.inputs().get(index).script(), tx.getVersion());
            byte[] encoded = app.untrustedHashSign(target.path(), "", tx.getLocktime(), 0x41);
            BsvSigningRequest.Signature signature = new BsvSigningRequest.Signature(target.slot(), Utils.bytesToHex(encoded));
            try { request.verify(signature); }
            catch(IllegalArgumentException e) { throw new DeviceException("Ledger returned an invalid BSV signature", e); }
            signatures.add(signature);
        }
        BsvSigningRequest.Result result = new BsvSigningRequest.Result(request.id(), signatures);
        request.apply(result); // Validate the entire response before returning anything to the wallet.
        return result;
    }

    private void requireMainnet() throws DeviceException {
        if(Network.get() != Network.MAINNET) throw new DeviceException("This Ledger BSV adapter currently supports mainnet account encoding only");
    }
}
