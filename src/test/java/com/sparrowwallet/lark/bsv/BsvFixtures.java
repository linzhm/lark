/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.bsv;

import com.fasterxml.jackson.databind.*;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.protocol.Transaction;
import java.util.*;

/** Only published BIP32 test keys and deliberately synthetic parents. */
public final class BsvFixtures {
    public static final ObjectMapper JSON = new ObjectMapper();
    public static final JsonNode DATA;
    static {
        try { DATA = JSON.readTree(BsvFixtures.class.getResourceAsStream("vectors.json")); }
        catch(Exception e) { throw new ExceptionInInitializerError(e); }
    }
    public static JsonNode vector(int index) { return DATA.get("fixtures").get(index); }
    public static BsvAccount account() { return new BsvAccount("m/44'/0'/0'", DATA.get("account").asText()); }
    public static BsvSigningRequest request(int index) {
        JsonNode fixture = vector(index);
        return new BsvSigningRequest(new Transaction(Utils.hexToBytes(fixture.get("transaction").asText())),
                list(fixture.get("inputs"), BsvSigningRequest.Input.class), list(fixture.get("targets"), BsvSigningRequest.Target.class),
                list(fixture.get("existing"), BsvSigningRequest.Signature.class));
    }
    public static <T> List<T> list(JsonNode node, Class<T> type) {
        List<T> result = new ArrayList<>();
        node.forEach(n -> result.add(JSON.convertValue(n, type)));
        return result;
    }
    public static BsvSigningRequest.Signature signature(int fixture, int input, int sighash) {
        var request = request(fixture);
        return new BsvSigningRequest.Signature(request.targets().get(input).slot(), vector(fixture).get("signatures").get(input + ":" + String.format("%02x", sighash)).asText());
    }
}
