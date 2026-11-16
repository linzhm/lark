/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.lark.bsv;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.*;
import java.util.List;

/** Public-only account identity. An account xpub fingerprint is never substituted for a root fingerprint. */
public record BsvAccount(String path, String xpub) {
    public BsvAccount {
        List<ChildNumber> nodes = KeyDerivation.parsePath(path);
        if(nodes.size() != 3 || nodes.stream().anyMatch(n -> !n.isHardened()) || nodes.getFirst().num() != 44 ||
                (nodes.get(1).num() != 0 && nodes.get(1).num() != 145)) {
            throw new IllegalArgumentException("Ledger BCH requires an explicit m/44'/0' or m/44'/145' account path");
        }
        path = KeyDerivation.writePath(nodes);
        ExtendedKey key = ExtendedKey.fromDescriptor(xpub, true);
        if(!key.getKey().isPubKeyOnly() || key.getKey().getDepth() != 3 || !key.getKeyChildNumber().equals(nodes.getLast()) ||
                !key.getExtendedKey(ExtendedKey.Header.xpub).equals(xpub)) throw new IllegalArgumentException("Expected complete mainnet account xpub");
    }

    public ECKey derive(String fullPath) {
        List<ChildNumber> account = KeyDerivation.parsePath(path);
        List<ChildNumber> target = KeyDerivation.parsePath(fullPath);
        if(target.size() != 5 || !target.subList(0, 3).equals(account) ||
                target.get(3).isHardened() || target.get(4).isHardened() || target.get(3).num() > 1) {
            throw new IllegalArgumentException("Signing path is outside the selected account");
        }
        DeterministicKey key = ExtendedKey.fromDescriptor(xpub, true).getKey();
        for(ChildNumber child : target.subList(3, 5)) key = HDKeyDerivation.deriveChildKey(key, child);
        return ECKey.fromPublicOnly(key.getPubKey());
    }
}
