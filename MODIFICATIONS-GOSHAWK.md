# Goshawk changes to Lark — 2026-11-16

Based on Sparrow Wallet's Lark, Apache-2.0, commit
`4eaaf9d2ef242164c801ab21247e616e5c4ef8f7`. Original LICENSE and source history
are preserved. Modified upstream Java files carry a dated modification notice.

- Add an explicit BSV/BCH API on the existing Lark discovery/operation lock,
  LedgerClient, legacy device and Btchip implementation.
- Add immutable BSV request/result/account models, signature admission, partial
  signing, transaction finalization and bounded Goshawk signing JSON.
- Correct app identity parsing, raw input framing and full transaction-version
  propagation. Add explicit `0x41` signing and full-output review without fallback.
- Bound first/continuation HID reads and reject overlapping exchange, short writes
  and malformed framing. Preserve existing Bitcoin API entry points.
- Add selected-device app switching, full-xpub pairing, address/message checks and
  model-scoped previous-transaction work budgets.
- Add offline tests and independently generated BitcoinX oracle fixtures.

See `docs/bsv-ledger.md` for scope, reference commits and physical-test limitations.

## 2026-11-16 correction

P2SH recovery was removed; all BSV inputs require P2PKH or bare multisig. ForkID
hashing now uses the maintained Drongo BSV implementation, not a witness API.
Goshawk's existing hardware entry now calls this BSV API. Root fingerprint import
requests the actual value from a paired device and never fabricates one.
