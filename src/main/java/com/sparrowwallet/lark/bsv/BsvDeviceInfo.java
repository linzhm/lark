/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.bsv;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import java.nio.charset.StandardCharsets;

/** Transport selection only; wallet identity requires a full account-xpub comparison. */
public record BsvDeviceInfo(String path, String model, String identity, String state,
                            String app, String appVersion, String detail) {
    public String shortIdentifier() { return identity.substring(0, 8); }
    public BsvDeviceInfo withPathIdentity() {
        return new BsvDeviceInfo(path, model, Sha256Hash.of((identity + ":" + path).getBytes(StandardCharsets.UTF_8)).toString(),
                state, app, appVersion, detail);
    }
}
