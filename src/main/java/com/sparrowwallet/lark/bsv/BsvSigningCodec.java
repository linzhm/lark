/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.bsv;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Transaction;
import java.util.*;

/** Bounded Goshawk signing JSON. This is neither PSBT nor ElectrumSVP's JSON format. */
public final class BsvSigningCodec {
    public static final int MAX_BYTES = 4_000_000;
    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16).maxNumberLength(20)
                    .maxStringLength(BsvSigningRequest.MAX_TRANSACTION_BYTES * 2).build()).build());
    private BsvSigningCodec() {}

    public record RequestEnvelope(String format, int version, String chain, String requestId, String transaction,
                                  List<BsvSigningRequest.Input> inputs, List<BsvSigningRequest.Target> targets,
                                  List<BsvSigningRequest.Signature> signatures) {}
    public record ResultEnvelope(String format, int version, String chain, String requestId,
                                 List<BsvSigningRequest.Signature> signatures) {}

    public static byte[] encodeRequest(BsvSigningRequest request) {
        List<BsvSigningRequest.Signature> signatures = request.signatures().entrySet().stream()
                .sorted(Comparator.comparing((Map.Entry<BsvSigningRequest.Slot, String> e) -> e.getKey().inputIndex()).thenComparing(e -> e.getKey().publicKey()))
                .map(e -> new BsvSigningRequest.Signature(e.getKey(), e.getValue())).toList();
        return write(new RequestEnvelope("goshawk-signing-request", 1, "BSV", request.id(),
                Utils.bytesToHex(request.transaction().bitcoinSerialize(false)), request.inputs(), request.targets(), signatures));
    }

    public static BsvSigningRequest decodeRequest(byte[] bytes) {
        RequestEnvelope envelope = read(bytes, RequestEnvelope.class);
        if(envelope == null || envelope.inputs() == null || envelope.targets() == null || envelope.signatures() == null || !"goshawk-signing-request".equals(envelope.format()) || envelope.version() != 1 || !"BSV".equals(envelope.chain())) throw new IllegalArgumentException("Unsupported signing request format/chain");
        if(envelope.transaction() == null || envelope.transaction().length() > BsvSigningRequest.MAX_TRANSACTION_BYTES * 2) throw new IllegalArgumentException("Transaction byte budget exceeded");
        byte[] raw = Utils.hexToBytes(envelope.transaction());
        Transaction transaction = new Transaction(raw);
        BsvSigningRequest.requireNonWitness(transaction);
        if(!Arrays.equals(raw, transaction.bitcoinSerialize(false))) throw new IllegalArgumentException("Noncanonical or trailing transaction data");
        BsvSigningRequest request = new BsvSigningRequest(transaction, envelope.inputs(), envelope.targets(), envelope.signatures());
        if(!request.id().equals(envelope.requestId())) throw new IllegalArgumentException("Signing request commitment mismatch");
        return request;
    }

    public static byte[] encodeResult(BsvSigningRequest.Result result) {
        return write(new ResultEnvelope("goshawk-signing-result", 1, "BSV", result.requestId(), result.signatures()));
    }

    public static BsvSigningRequest.Result decodeResult(byte[] bytes) {
        ResultEnvelope envelope = read(bytes, ResultEnvelope.class);
        if(envelope == null || envelope.requestId() == null || envelope.signatures() == null || !"goshawk-signing-result".equals(envelope.format()) || envelope.version() != 1 || !"BSV".equals(envelope.chain()) || envelope.signatures().size() > 256) throw new IllegalArgumentException("Unsupported signing result");
        return new BsvSigningRequest.Result(envelope.requestId(), envelope.signatures());
    }

    private static byte[] write(Object object) {
        try {
            byte[] bytes = MAPPER.writeValueAsBytes(object);
            if(bytes.length > MAX_BYTES) throw new IllegalArgumentException("Signing envelope exceeds host byte budget");
            return bytes;
        } catch(JsonProcessingException e) { throw new IllegalArgumentException("Cannot encode signing envelope", e); }
    }

    private static <T> T read(byte[] bytes, Class<T> type) {
        if(bytes == null || bytes.length > MAX_BYTES) throw new IllegalArgumentException("Signing envelope exceeds host byte budget");
        try { return MAPPER.readerFor(type).with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readValue(bytes); }
        catch(java.io.IOException | RuntimeException e) { throw new IllegalArgumentException("Invalid signing envelope", e); }
    }
}
