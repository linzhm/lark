// Modified for Goshawk BSV integration, 2026-11-16.
package com.sparrowwallet.lark.ledger;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.protocol.VarInt;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.drongo.Version;
import com.sparrowwallet.lark.ledger.command.CommandBuilder;
import com.sparrowwallet.lark.ledger.command.DefaultInsType;
import com.sparrowwallet.lark.ledger.wallet.WalletPolicy;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public abstract class LedgerDevice implements Closeable {
    protected final Transport transport;

    public LedgerDevice(Transport transport) {
        this.transport = transport;
    }

    /** Selects the Bitcoin protocol while retaining ownership of one transport. */
    public static LedgerDevice openBitcoin(Transport transport) throws DeviceException {
        try {
            NewLedgerDevice modern = new NewLedgerDevice(transport);
            LedgerVersion version = modern.getVersion();
            if(version.name().equals("Bitcoin Cash")) throw new DeviceException("Bitcoin Cash requires the explicit BSV API, not Bitcoin PSBT signing");
            return version.isLegacy() ? new LegacyLedgerDevice(transport, version) : modern;
        } catch(Exception e) {
            try { transport.close(); } catch(IOException ignored) { }
            throw new DeviceException(e.getMessage(), e);
        }
    }

    /**
     * Queries the hardware wallet for the currently running app's name, version and state flags.
     *
     * @return the LedgerVersion object
     * @throws DeviceException on an error
     */
    public LedgerVersion getVersion() throws DeviceException {
        Transport.Response response = makeRequest(new APDUCommand(CommandBuilder.CLA_DEFAULT, DefaultInsType.GET_VERSION.getValue(), 0, 0, new byte[0]));

        if(response.sw() != 0x9000) {
            throw new LedgerResponseException(response, DefaultInsType.GET_VERSION);
        }

        return parseVersion(response.data());
    }

    public static LedgerVersion parseVersion(byte[] data) throws DeviceException {
        if(data.length < 3 || data[0] != 1) throw new DeviceException("Invalid Ledger app identity");
        try {
            int offset = 1;
            int nameLength = data[offset++] & 0xff;
            if(nameLength == 0 || offset + nameLength >= data.length) throw new IllegalArgumentException();
            String name = new String(data, offset, nameLength, StandardCharsets.US_ASCII);
            offset += nameLength;
            int versionLength = data[offset++] & 0xff;
            if(versionLength == 0 || offset + versionLength > data.length) throw new IllegalArgumentException();
            String version = new String(data, offset, versionLength, StandardCharsets.US_ASCII);
            if(!version.matches("[0-9]+\\.[0-9]+\\.[0-9]+")) throw new IllegalArgumentException();
            offset += versionLength;
            byte[] flags = new byte[0];
            if(offset < data.length) {
                int flagLength = data[offset++] & 0xff;
                if(offset + flagLength != data.length) throw new IllegalArgumentException();
                flags = Arrays.copyOfRange(data, offset, data.length);
            }
            return new LedgerVersion(name, new Version(version), flags);
        } catch(RuntimeException e) {
            throw new DeviceException("Malformed Ledger app identity", e);
        }
    }

    public abstract String getMasterFingerprint() throws DeviceException;

    public abstract ExtendedKey getExtendedPubkey(String path, boolean display) throws DeviceException;

    public abstract List<Signature> signPsbt(PSBT psbt, WalletPolicy walletPolicy, Sha256Hash walletHmac) throws DeviceException;

    public abstract WalletRegistration registerWallet(WalletPolicy walletPolicy) throws DeviceException;

    public abstract String signMessage(String message, String path) throws DeviceException;

    public abstract String getWalletAddress(WalletPolicy walletPolicy, Sha256Hash walletHmac, int change, int addressIndex, boolean display) throws DeviceException;

    protected Transport.Response makeRequest(APDUCommand apduCommand) throws DeviceException {
        try {
            return transport.apduExchange(apduCommand);
        } catch(LedgerTransportException e) {
            return e.getResponse();
        }
    }

    @Override
    public void close() {
        try {
            transport.close();
        } catch(IOException e) {
            throw new RuntimeException(e);
        }
    }

    public record LedgerVersion(String name, Version version, byte[] state) {
        public boolean isLegacy() {
            return name.equals("Bitcoin Cash") || version.compareTo(new Version("2.0.99")) < 0 || name.contains("Legacy");
        }
    }

    public record Signature(int inputIndex, ECKey ecKey, TransactionSignature transactionSignature) {}
    public record WalletRegistration(Sha256Hash id, Sha256Hash hmac) {}
}
