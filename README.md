<!-- Modified for Goshawk BSV integration, 2026-11-16; see MODIFICATIONS-GOSHAWK.md. -->
# Lark

Lark is Java library for interacting with USB hardware wallets in Bitcoin related functions. 
The initial implementation is a port of the Python library [HWI](https://github.com/bitcoin-core/HWI), but the library has since been extended to support additional functionality.

The following hardware wallets (for all models, unless specified) are supported:
- Coldcard
- Trezor
- Ledger
- BitBox02
- Jade
- Keepkey
- OneKey (Classic 1S and Pro)

## Example usage

```java
Lark lark = new Lark();
List<HardwareClient> clients = lark.enumerate();

for(HardwareClient client : clients) {
    ExtendedKey xpub = lark.getPubKeyAtPath(client.getType(), client.getPath(), "m/84'/1'/0'");
}
```
## Goshawk BSV integration

This fork adds an explicit BCH/BSV route over the existing Java implementation.
See [API, validation and limits](docs/bsv-ledger.md) and
[modification record](MODIFICATIONS-GOSHAWK.md). It is experimental and has no
Java-device certification yet; the original Bitcoin PSBT API remains separate.
