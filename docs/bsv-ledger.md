# Goshawk BSV Ledger adapter

This fork extends Lark's existing `LedgerClient`, HID transport, legacy device and
`Btchip` commands. It does not introduce a Python service or a second USB driver.
It is experimental host integration, not a certified hardware-wallet release.

## Public API

Goshawk calls only the explicit BSV API. Upstream hardware classes remain for source compatibility, but are not alternate signing routes in Goshawk. As with other
Lark operations, callers must run device work off the GUI thread:

```java
Lark lark = new Lark();
List<BsvDeviceInfo> devices = lark.enumerateBsvLedgers();
// The caller selects a specific device and, if needed, requests opening BCH.
BsvDeviceInfo ready = lark.openBsvLedgerApp(selected);
BsvAccount account = lark.getBsvAccount(ready.path(), "m/44'/0'/0'");
String address = lark.displayBsvAddress(ready.path(), account, "m/44'/0'/0'/0/0");
String messageSignature = lark.signBsvMessage(ready.path(), account,
        "m/44'/0'/0'/0/0", message);
BsvSigningRequest.VerificationPlan verification = lark.planBsvSigning(ready.path(), request);
BsvSigningRequest.Result result = lark.signBsvTransaction(ready.path(), account,
        request, BsvSigningRequest.VerificationPolicy.REQUIRE_TRUSTED);
BsvSigningRequest signed = request.apply(result);
```

Discovery does not request a restricted root key. App switching uses only the
selected transport identity, never the first device in a refreshed list. Model
family separates duplicate serial fields across Nano S/S Plus/X; same-model
collisions are disambiguated by USB path. Such a path may change on reconnect,
in which case explicit selection is required again. A device identity is not
wallet ownership: operations compare the complete account xpub and derive the
requested child public key from it. No fabricated root fingerprint is returned.

`m/44'/0'/account'` and `m/44'/145'/account'` are explicit account paths; this adapter
does not migrate paths or enable coin type 236. The parent fingerprint in an
account xpub remains the actual parent fingerprint. Key import is public-only.
Mainnet account encoding is the current device scope.

Each application switch has a 30-second polling window; a scan already in flight
can take longer (up to five seconds per attached Ledger). HID exchanges have a
single bounded deadline covering the first and continuation packets. Locked,
wrong-app, missing/ambiguous and unavailable states remain distinct. Transport
failures do not prove another application owns the device. No process is killed,
PIN entered on the host, application installed or firmware changed.

## Transactions and assurance

`BsvSigningRequest` takes a detached non-witness transaction with empty scriptSigs,
explicit amounts and scripts for every input, compressed public keys in script
order, optional complete raw parents, selected targets and existing signatures.
The supported input models are P2PKH and bare multisig. P2SH inputs, including historical recovery, are rejected.

The host validates the six ForkID-0 digest combinations `41/42/43/c1/c2/c3`.
Ledger BCH signs only `0x41`; arbitrary scripts, witness/Taproot, other Ledger
models and other sighash modes are not admitted to its device route. Device
outputs currently must be P2PKH. This is narrower than arbitrary BSV transactions.
All outputs are sent for review; no output is hidden as change. Signed bytes
remain ordinary non-witness BSV transactions, never witness transactions or BEEF.

Present parents are checked against each outpoint, value and locking script
before device work, including synthetic coinbase parents. Trusted-input work has
model-specific byte/script/command budgets; these are host policy, not measured
firmware maxima. Missing/oversized parents require the caller to explicitly
choose `ALLOW_UNVERIFIED` after informing the user. Malformed parents are rejected.
An actual device rejection or error never triggers reduced verification or an
older output-finalization fallback. Trusted parent verification does not establish
chain inclusion, unspentness, selected-chain coinbase maturity or acceptable fees.

Every existing and returned signature is verified against the exact BSV digest,
public key and sighash. Results are bound to the locally retained request. Duplicate,
unrequested, replacement, malformed or invalid signatures reject the whole result.
Requests remain unchanged after success, rejection, timeout or invalid response;
`apply` returns a new request. Partial results preserve existing cosigner signatures.
Finalization requires each input threshold and emits signatures in script order.

`BsvSigningCodec` is bounded, versioned **Goshawk signing JSON**, not ElectrumSVP JSON
or PSBT. It includes explicit BSV chain/format identifiers and retains incomplete
signatures. Do not admit a result against a request supplied by an untrusted signer.
The Goshawk parent project supplies a strict editor-container-to-BSV bridge. This library contains no networking, broadcast or payment acknowledgement.

## Evidence and provenance

Behavioral reference: [ElectrumSVP hardware branch](https://github.com/linzhm/ElectrumSVP/tree/codex/hardware-wallet-support),
pinned at `fff115ea3233ad7045c7a67a9479a9d1e1310c9e` (hardware implementation
`1dd2a8aa91f996b684dd347528d28bf56b88b48a`). Its validation is Python/Qt evidence,
not certification of this Java implementation. Its source is Open BSV licensed;
no Python source or vendor dependencies were imported into this Apache-2.0 fork.
The Java changes extend the existing Apache-2.0 Lark implementation and implement
protocol/behavior requirements independently. Original licenses remain unchanged.

Protocol checks used [Ledger's legacy host protocol](https://github.com/LedgerHQ/btchip-python/blob/master/btchip/btchip.py)
and the [BSV ForkID digest description](https://github.com/bitcoin-sv/bitcoin-sv/blob/master/doc/abc/replay-protected-sighash.md).
Tests use freshly generated BitcoinX 0.9 oracle vectors with the public BIP32 test
seed, synthetic coinbase parents and no user/device data. `tools/generate-bsv-vectors.py`
regenerates the fixtures offline when BitcoinX 0.9 is installed; it is not a runtime dependency.

Run the offline tests from the Goshawk checkout (Java 25):

```sh
./gradlew :lark:test --tests '*Bsv*Test' --tests '*HIDTransportTest'
```

Do not run the upstream `EnumerateTest` as an offline check: it accesses physical
USB devices. No device operation, real wallet, real UTXO, funded transfer or broadcast
was used for this port. A fresh physical matrix is required before enabling BSV
signing in a released wallet UI. S Plus/X trusted-parent and multisig tests remain
unverified even in the reference project's physical matrix.
