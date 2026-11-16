/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.bsv;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Detached BSV transaction intent. No device, wallet, PSBT, or network side effects. */
public final class BsvSigningRequest {
    public enum VerificationPolicy { REQUIRE_TRUSTED, ALLOW_UNVERIFIED }
    public record VerificationPlan(boolean trusted, String reason) {}
    public static final Set<Integer> SIGHASHES = Set.of(0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3);
    public static final int MAX_TRANSACTION_BYTES = 1_000_000; // Host work budget, not consensus.
    private final byte[] unsignedTransaction;
    private final List<Input> inputs;
    private final List<Target> targets;
    private final Map<Slot, String> signatures;
    private final String id;

    public record Slot(int inputIndex, String publicKey) {
        public Slot {
            if(inputIndex < 0) throw new IllegalArgumentException("Negative input index");
            publicKey = normalizedKey(publicKey);
        }
    }

    public record Target(Slot slot, String path, int sighash) {
        public Target {
            Objects.requireNonNull(slot);
            Objects.requireNonNull(path);
            if(!SIGHASHES.contains(sighash)) throw new IllegalArgumentException("Unsupported BSV sighash");
        }
    }

    /** Hex fields make the record deeply immutable. Key order is the script's order. */
    public record Input(long value, String lockingScript, String signingScript,
                        List<String> publicKeys, String previousTransaction) {
        public Input {
            if(value < 0 || value > Transaction.MAX_SATOSHIS) throw new IllegalArgumentException("Invalid input amount");
            if(lockingScript.length() > 16384 || signingScript.length() > 16384) throw new IllegalArgumentException("Signing script exceeds host byte budget");
            lockingScript = normalizedHex(lockingScript);
            signingScript = normalizedHex(signingScript);
            publicKeys = publicKeys.stream().map(BsvSigningRequest::normalizedKey).toList();
            if(new HashSet<>(publicKeys).size() != publicKeys.size()) throw new IllegalArgumentException("Duplicate script key");
            if(previousTransaction != null) {
                if(previousTransaction.length() > MAX_TRANSACTION_BYTES * 2) throw new IllegalArgumentException("Parent exceeds host byte budget");
                previousTransaction = normalizedHex(previousTransaction);
            }
            Script locking = new Script(Utils.hexToBytes(lockingScript));
            Script signing = new Script(Utils.hexToBytes(signingScript));
            BsvTransaction.requireSigningScript(locking);
            if(!lockingScript.equals(signingScript)) throw new IllegalArgumentException("Signing script must equal the previous output script");
            if(ScriptType.P2PKH.isScriptType(signing)) {
                if(publicKeys.size() != 1 || !Arrays.equals(signing.getPubKeyHash(), key(publicKeys.getFirst()).getPubKeyHash())) {
                    throw new IllegalArgumentException("P2PKH public key does not match script");
                }
            } else if(ScriptType.MULTISIG.isScriptType(signing)) {
                List<String> actual = Arrays.stream(ScriptType.MULTISIG.getPublicKeysFromScript(signing))
                        .map(k -> Utils.bytesToHex(k.getPubKey())).toList();
                if(!actual.equals(publicKeys)) throw new IllegalArgumentException("Multisig keys/order do not match script");
                int threshold = ScriptType.MULTISIG.getThreshold(signing);
                if(threshold < 1 || threshold > publicKeys.size()) throw new IllegalArgumentException("Invalid multisig threshold");
            } else {
                throw new IllegalArgumentException("Only P2PKH and explicit multisig signing scripts are supported");
            }
        }

        public Script script() { return new Script(Utils.hexToBytes(signingScript)); }
        public int threshold() { return ScriptType.P2PKH.isScriptType(script()) ? 1 : ScriptType.MULTISIG.getThreshold(script()); }
    }

    public record Signature(Slot slot, String signature) {
        public Signature { Objects.requireNonNull(slot); signature = normalizedHex(signature); }
    }

    public record Result(String requestId, List<Signature> signatures) {
        public Result { Objects.requireNonNull(requestId); signatures = List.copyOf(signatures); }
    }

    public BsvSigningRequest(Transaction transaction, List<Input> inputs, List<Target> targets,
                             List<Signature> existingSignatures) {
        BsvTransaction.requireTransaction(transaction);
        if(transaction.getInputs().isEmpty() || transaction.getOutputs().isEmpty() || transaction.isCoinBase()) {
            throw new IllegalArgumentException("A spending transaction with inputs and outputs is required");
        }
        if(transaction.hasScriptSigs()) throw new IllegalArgumentException("Pass unlocking signatures separately from the unsigned transaction");
        uint32(transaction.getVersion()); uint32(transaction.getLocktime());
        for(TransactionInput input : transaction.getInputs()) { uint32(input.getSequenceNumber()); uint32(input.getOutpoint().getIndex()); }
        if(targets.size() > 256 || existingSignatures.size() > 4096) throw new IllegalArgumentException("Signature work budget exceeded");
        unsignedTransaction = transaction.bitcoinSerialize(false);
        if(unsignedTransaction.length > MAX_TRANSACTION_BYTES) throw new IllegalArgumentException("Transaction exceeds host byte budget");
        Transaction snapshot = transaction();
        if(inputs.size() != snapshot.getInputs().size()) throw new IllegalArgumentException("Every input needs its amount and script");
        this.inputs = List.copyOf(inputs);
        this.targets = List.copyOf(targets);
        Set<String> outpoints = new HashSet<>();
        long totalIn = 0, totalOut = 0;
        for(int i = 0; i < inputs.size(); i++) {
            if(!outpoints.add(Utils.bytesToHex(snapshot.getInputs().get(i).getOutpoint().bitcoinSerialize()))) throw new IllegalArgumentException("Duplicate outpoint");
            totalIn = Math.addExact(totalIn, inputs.get(i).value());
            validateParent(i);
        }
        for(TransactionOutput output : snapshot.getOutputs()) {
            if(output.getValue() < 0 || output.getValue() > Transaction.MAX_SATOSHIS) throw new IllegalArgumentException("Invalid output amount");
            totalOut = Math.addExact(totalOut, output.getValue());
        }
        if(totalIn > Transaction.MAX_SATOSHIS || totalOut > totalIn) throw new IllegalArgumentException("Invalid transaction amounts");
        Set<Slot> requested = new HashSet<>();
        for(Target target : targets) {
            validateSlot(target.slot());
            if(!requested.add(target.slot())) throw new IllegalArgumentException("Duplicate target");
            hash(target.slot().inputIndex(), target.sighash());
        }
        Map<Slot, String> accepted = new LinkedHashMap<>();
        for(Signature signature : existingSignatures) {
            verify(signature);
            if(accepted.putIfAbsent(signature.slot(), signature.signature()) != null) throw new IllegalArgumentException("Duplicate signature");
        }
        signatures = Map.copyOf(accepted);
        id = commitment();
    }

    public String id() { return id; }
    public Transaction transaction() { return new Transaction(unsignedTransaction.clone()); }
    public List<Input> inputs() { return inputs; }
    public List<Target> targets() { return targets; }
    public Map<Slot, String> signatures() { return signatures; }

    /** Applies only an authenticated result to a new request; the retained request is never mutated. */
    public BsvSigningRequest apply(Result result) {
        if(!id.equals(result.requestId())) throw new IllegalArgumentException("Signing result belongs to a different request");
        Map<Slot, Target> allowed = new HashMap<>();
        targets.forEach(t -> allowed.put(t.slot(), t));
        Map<Slot, String> combined = new LinkedHashMap<>(signatures);
        for(Signature signature : result.signatures()) {
            Target target = allowed.get(signature.slot());
            if(target == null || sighash(signature.signature()) != target.sighash()) throw new IllegalArgumentException("Unrequested signature or sighash");
            verify(signature);
            if(combined.putIfAbsent(signature.slot(), signature.signature()) != null) throw new IllegalArgumentException("Signature replacement or duplicate result");
        }
        return new BsvSigningRequest(transaction(), inputs, targets,
                combined.entrySet().stream().map(e -> new Signature(e.getKey(), e.getValue())).toList());
    }

    public Sha256Hash hash(int index, int sighash) {
        if(index < 0 || index >= inputs.size() || !SIGHASHES.contains(sighash)) throw new IllegalArgumentException("Invalid BSV signing target");
        Transaction tx = transaction();
        if((sighash & 0x1f) == 3 && index >= tx.getOutputs().size()) throw new IllegalArgumentException("SINGLE requires a corresponding output");
        // ForkID 0 uses this preimage algorithm. The transaction remains non-witness.
        return BsvTransaction.signatureHash(tx, index, inputs.get(index).script(), inputs.get(index).value(), sighash);
    }

    public void verify(Signature signature) {
        validateSlot(signature.slot());
        byte[] encoded = Utils.hexToBytes(signature.signature());
        if(encoded.length < 9 || encoded.length > 73) throw new IllegalArgumentException("Invalid signature length");
        try {
            byte[] der = Arrays.copyOf(encoded, encoded.length - 1);
            ECDSASignature decoded = ECDSASignature.decodeFromDER(der);
            if(!decoded.isCanonical() || !Arrays.equals(der, decoded.encodeToDER()) ||
                    !decoded.verify(hash(signature.slot().inputIndex(), encoded[encoded.length - 1] & 0xff).getBytes(), key(signature.slot().publicKey()).getPubKey())) {
                throw new IllegalArgumentException("Invalid BSV signature");
            }
        } catch(SignatureDecodeException e) {
            throw new IllegalArgumentException("Invalid DER signature", e);
        }
    }

    public boolean isComplete() {
        for(int i = 0; i < inputs.size(); i++) {
            int index = i;
            long count = inputs.get(i).publicKeys().stream().filter(k -> signatures.containsKey(new Slot(index, k))).count();
            if(count < inputs.get(i).threshold()) return false;
        }
        return true;
    }

    /** Finalization is explicit; partial requests remain exportable without inventing scriptSig placeholders. */
    public Transaction finalizeTransaction() {
        if(!isComplete()) throw new IllegalStateException("More signatures are required");
        Transaction tx = transaction();
        for(int i = 0; i < inputs.size(); i++) {
            Input input = inputs.get(i);
            List<ScriptChunk> chunks = new ArrayList<>();
            if(ScriptType.P2PKH.isScriptType(input.script())) {
                String pub = input.publicKeys().getFirst();
                chunks.add(ScriptChunk.fromData(Utils.hexToBytes(signatures.get(new Slot(i, pub)))));
                chunks.add(ScriptChunk.fromData(Utils.hexToBytes(pub)));
            } else {
                chunks.add(ScriptChunk.fromOpcode(ScriptOpCodes.OP_0));
                int count = 0;
                for(String pub : input.publicKeys()) {
                    String signature = signatures.get(new Slot(i, pub));
                    if(signature != null && count++ < input.threshold()) chunks.add(ScriptChunk.fromData(Utils.hexToBytes(signature)));
                }
            }
            tx.getInputs().get(i).setScriptBytes(new Script(chunks).getProgram());
        }
        return tx;
    }

    private void validateSlot(Slot slot) {
        if(slot.inputIndex() >= inputs.size() || !inputs.get(slot.inputIndex()).publicKeys().contains(slot.publicKey())) throw new IllegalArgumentException("Signature key does not belong to input script");
    }

    private void validateParent(int index) {
        Input input = inputs.get(index);
        if(input.previousTransaction() == null) return;
        byte[] bytes = Utils.hexToBytes(input.previousTransaction());
        Transaction parent;
        try { parent = new Transaction(bytes); }
        catch(RuntimeException e) { throw new IllegalArgumentException("Invalid previous transaction", e); }
        requireNonWitness(parent);
        if(!Arrays.equals(bytes, parent.bitcoinSerialize(false))) throw new IllegalArgumentException("Noncanonical or trailing parent bytes");
        TransactionOutPoint outpoint = transaction().getInputs().get(index).getOutpoint();
        if(!parent.getTxId().equals(outpoint.getHash()) || outpoint.getIndex() >= parent.getOutputs().size()) throw new IllegalArgumentException("Parent/outpoint mismatch");
        TransactionOutput output = parent.getOutputs().get((int)outpoint.getIndex());
        if(output.getValue() != input.value() || !Utils.bytesToHex(output.getScriptBytes()).equals(input.lockingScript())) throw new IllegalArgumentException("Parent amount/script mismatch");
    }

    private String commitment() {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        field(bytes, "Goshawk/BSV/signing/v1");
        field(bytes, Utils.bytesToHex(unsignedTransaction));
        for(Input input : inputs) {
            field(bytes, Long.toString(input.value())); field(bytes, input.lockingScript()); field(bytes, input.signingScript());
            field(bytes, Integer.toString(input.publicKeys().size()));
            input.publicKeys().forEach(k -> field(bytes, k));
        }
        for(Target target : targets) {
            field(bytes, target.slot().toString()); field(bytes, target.path()); field(bytes, Integer.toString(target.sighash()));
        }
        return Sha256Hash.of(bytes.toByteArray()).toString();
    }

    private static void field(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeBytes(new VarInt(bytes.length).encode()); out.writeBytes(bytes);
    }

    public static void requireNonWitness(Transaction tx) {
        if(tx.isSegwit() || tx.hasWitnesses()) throw new IllegalArgumentException("BSV signing does not accept witness transactions");
    }
    public static ECKey key(String hex) { return ECKey.fromPublicOnly(Utils.hexToBytes(hex)); }
    private static String normalizedKey(String hex) {
        byte[] bytes = Utils.hexToBytes(hex);
        if(bytes.length != 33) throw new IllegalArgumentException("Compressed public key required");
        return Utils.bytesToHex(ECKey.fromPublicOnly(bytes).getPubKey(true));
    }
    private static void uint32(long value) { if(value < 0 || value > 0xffffffffL) throw new IllegalArgumentException("Transaction field exceeds uint32"); }
    private static String normalizedHex(String value) { return Utils.bytesToHex(Utils.hexToBytes(Objects.requireNonNull(value))); }
    private static int sighash(String signature) {
        byte[] bytes = Utils.hexToBytes(signature);
        if(bytes.length == 0) throw new IllegalArgumentException("Empty signature");
        return bytes[bytes.length - 1] & 0xff;
    }
}
