package org.aion.zero.types;

import org.aion.crypto.HashUtil;
import org.aion.interfaces.block.BlockHeader;
import org.aion.mcf.types.AbstractBlockHeader;
import org.aion.rlp.RLP;
import org.aion.rlp.RLPList;
import org.aion.types.AionAddress;
import org.aion.util.bytes.ByteUtil;
import org.aion.util.types.AddressUtils;
import org.aion.zero.exceptions.HeaderStructureException;
import org.json.JSONObject;

import java.math.BigInteger;
import java.util.Objects;

import static org.aion.crypto.HashUtil.EMPTY_TRIE_HASH;
import static org.aion.util.bytes.ByteUtil.*;
import static org.aion.util.time.TimeUtils.longToDateTime;

/**
 * Represents a PoS block on a chain implementing Unity Consensus.
 *
 */
public class StakedBlockHeader extends AbstractBlockHeader implements BlockHeader {

    private static final int RPL_BH_VERSION = 0,
            RPL_BH_NUMBER = 1,
            RPL_BH_PARENTHASH = 2,
            RPL_BH_COINBASE = 3,
            RPL_BH_STATEROOT = 4,
            RPL_BH_TXTRIE = 5,
            RPL_BH_RECEIPTTRIE = 6,
            RPL_BH_LOGSBLOOM = 7,
            RPL_BH_DIFFICULTY = 8,
            RPL_BH_EXTRADATA = 9,
            RPL_BH_NRG_CONSUMED = 10,
            RPL_BH_NRG_LIMIT = 11,
            RPL_BH_TIMESTAMP = 12,
            RPL_BH_SIGNATURE = 13,
            RPL_BH_SEED = 14;


    /*
     * The seed of this block. It should be a verifiable signature of the seed of the previous PoS block.
     */
    protected byte[] seed;


    /*
     * A verifiable signature of the encoding of this block (without this field). 
     * The signer should be the same signer as the signer of the seed.
     */
    protected byte[] signature;

    private byte[] mineHashBytes;

    // TODO: Update this
    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        obj.putOpt("version", oneByteToHexString(this.version));
        obj.putOpt("number", toHexString(longToBytes(this.number)));
        obj.putOpt("parentHash", toHexString(this.parentHash));
        obj.putOpt("coinBase", toHexString(this.coinbase.toByteArray()));
        obj.putOpt("stateRoot", toHexString(this.stateRoot));
        obj.putOpt("txTrieRoot", toHexString(this.txTrieRoot));
        obj.putOpt("receiptTrieRoot", toHexString(this.receiptTrieRoot));
        obj.putOpt("logsBloom", toHexString(this.logsBloom));
        obj.putOpt("difficulty", toHexString(this.difficulty));
        obj.putOpt("extraData", toHexString(this.extraData));
        obj.putOpt("energyConsumed", toHexString(longToBytes(this.energyConsumed)));
        obj.putOpt("energyLimit", toHexString(longToBytes(this.energyLimit)));
        obj.putOpt("timestamp", toHexString(longToBytes(this.timestamp)));

        return obj;
    }

    public StakedBlockHeader(byte[] encoded) {
        this((RLPList) RLP.decode2(encoded).get(0));
    }

    public StakedBlockHeader(RLPList rlpHeader) {

        // Version
        byte[] versionBytes = rlpHeader.get(RPL_BH_VERSION).getRLPData();
        this.version = versionBytes.length == 1 ? versionBytes[0] : 1;

        // Number
        byte[] nrBytes = rlpHeader.get(RPL_BH_NUMBER).getRLPData();
        this.number = nrBytes == null ? 0 : (new BigInteger(1, nrBytes)).longValue();

        // ParentHash
        this.parentHash = rlpHeader.get(RPL_BH_PARENTHASH).getRLPData();

        // CoinBase
        byte[] data = rlpHeader.get(RPL_BH_COINBASE).getRLPData();
        if (data == null || data.length != AionAddress.LENGTH) {
            throw new IllegalArgumentException("Coinbase can not be null!");
        }
        this.coinbase = new AionAddress(data);

        // StateRoot
        this.stateRoot = rlpHeader.get(RPL_BH_STATEROOT).getRLPData();

        // TxTrieRoot
        this.txTrieRoot = rlpHeader.get(RPL_BH_TXTRIE).getRLPData();
        if (this.txTrieRoot == null) {
            this.txTrieRoot = EMPTY_TRIE_HASH;
        }

        // ReceiptTrieRoot
        this.receiptTrieRoot = rlpHeader.get(RPL_BH_RECEIPTTRIE).getRLPData();
        if (this.receiptTrieRoot == null) {
            this.receiptTrieRoot = EMPTY_TRIE_HASH;
        }

        // LogsBloom
        this.logsBloom = rlpHeader.get(RPL_BH_LOGSBLOOM).getRLPData();

        // Difficulty
        this.difficulty = rlpHeader.get(RPL_BH_DIFFICULTY).getRLPData();

        // ExtraData
        this.extraData = rlpHeader.get(RPL_BH_EXTRADATA).getRLPData();

        // Energy Consumed
        byte[] energyConsumedBytes = rlpHeader.get(RPL_BH_NRG_CONSUMED).getRLPData();
        this.energyConsumed =
                energyConsumedBytes == null
                        ? 0
                        : (new BigInteger(1, energyConsumedBytes).longValue());

        // Energy Limit
        byte[] energyLimitBytes = rlpHeader.get(RPL_BH_NRG_LIMIT).getRLPData();
        this.energyLimit =
                energyLimitBytes == null ? 0 : (new BigInteger(1, energyLimitBytes).longValue());

        // Timestamp
        byte[] tsBytes = rlpHeader.get(RPL_BH_TIMESTAMP).getRLPData();

        // TODO: not a huge concern, but how should we handle possible
        // overflows?
        this.timestamp = tsBytes == null ? 0 : (new BigInteger(1, tsBytes)).longValue();

        // Signature
        this.signature = rlpHeader.get(RPL_BH_SIGNATURE).getRLPData();

        // Seed
        this.seed = rlpHeader.get(RPL_BH_SEED).getRLPData();
    }

    /**
     * Copy constructor
     *
     * @param toCopy Block header to copy
     */
    public StakedBlockHeader(StakedBlockHeader toCopy) {

        // Copy version
        this.version = toCopy.getVersion();

        // Copy block number
        this.number = toCopy.getNumber();

        // Copy elements in parentHash
        this.parentHash = new byte[toCopy.getParentHash().length];
        System.arraycopy(toCopy.getParentHash(), 0, this.parentHash, 0, this.parentHash.length);

        // Copy elements in coinbase
        if (toCopy.coinbase == null) {
            throw new IllegalArgumentException("Coinbase can not be null!");
        } else {
            this.coinbase = toCopy.coinbase;
        }

        // Copy stateroot
        this.stateRoot = new byte[toCopy.getStateRoot().length];
        System.arraycopy(toCopy.getStateRoot(), 0, this.stateRoot, 0, this.stateRoot.length);

        // Copy txTrieRoot
        this.txTrieRoot = new byte[toCopy.getTxTrieRoot().length];
        System.arraycopy(toCopy.getTxTrieRoot(), 0, this.txTrieRoot, 0, this.txTrieRoot.length);

        // Copy receiptTreeRoot
        this.receiptTrieRoot = new byte[toCopy.getReceiptsRoot().length];
        System.arraycopy(
                toCopy.getReceiptsRoot(), 0, this.receiptTrieRoot, 0, this.receiptTrieRoot.length);

        // Copy logs bloom
        this.logsBloom = new byte[toCopy.getLogsBloom().length];
        System.arraycopy(toCopy.getLogsBloom(), 0, this.logsBloom, 0, this.logsBloom.length);

        // Copy difficulty
        this.difficulty = new byte[toCopy.getDifficulty().length];
        System.arraycopy(toCopy.getDifficulty(), 0, this.difficulty, 0, this.difficulty.length);

        // Copy extra data
        this.extraData = new byte[toCopy.getExtraData().length];
        System.arraycopy(toCopy.getExtraData(), 0, this.extraData, 0, this.extraData.length);

        // Copy energyConsumed
        this.energyConsumed = toCopy.getEnergyConsumed();

        // Copy energyLimit
        this.energyLimit = toCopy.getEnergyLimit();

        // Copy timestamp
        this.timestamp = toCopy.getTimestamp();

        // Copy signature
        this.signature = new byte[toCopy.getSignature().length];
        System.arraycopy(toCopy.getSignature(), 0, this.signature, 0, this.signature.length);

        // Copy seed
        this.seed = new byte[toCopy.getSeed().length];
        System.arraycopy(toCopy.getSeed(), 0, this.seed, 0, this.seed.length);
    }

    public StakedBlockHeader(
            byte version,
            long number,
            byte[] parentHash,
            AionAddress coinbase,
            byte[] logsBloom,
            byte[] difficulty,
            byte[] extraData,
            long energyConsumed,
            long energyLimit,
            long timestamp,
            byte[] signature,
            byte[] seed) {
        this.version = version;
        if (coinbase == null) {
            throw new IllegalArgumentException("Coinbase can not be null!");
        } else {
            this.coinbase = coinbase;
        }
        this.parentHash = parentHash;
        this.logsBloom = logsBloom;
        this.difficulty = difficulty;
        this.number = number;
        this.timestamp = timestamp;
        this.extraData = extraData;
        this.signature = signature;
        this.seed = seed;

        // Fields required for energy based VM
        this.energyConsumed = energyConsumed;
        this.energyLimit = energyLimit;
    }

    public byte[] getHash() {
        return HashUtil.h256(getEncoded());
    }

    public byte[] getEncoded() {
        return this.getEncoded(true); // with signature
    }

    public byte[] getEncodedWithoutSignature() {
        return this.getEncoded(false);
    }

    public byte[] getEncoded(boolean withSignature) {

        byte[] versionBytes = {this.version};

        byte[] RLPversion = RLP.encodeElement(versionBytes);
        byte[] number = RLP.encodeBigInteger(BigInteger.valueOf(this.number));
        byte[] parentHash = RLP.encodeElement(this.parentHash);
        byte[] coinbase = RLP.encodeElement(this.coinbase.toByteArray());
        byte[] stateRoot = RLP.encodeElement(this.stateRoot);

        if (txTrieRoot == null) {
            this.txTrieRoot = EMPTY_TRIE_HASH;
        }
        byte[] txTrieRoot = RLP.encodeElement(this.txTrieRoot);

        if (receiptTrieRoot == null) {
            this.receiptTrieRoot = EMPTY_TRIE_HASH;
        }
        byte[] receiptTrieRoot = RLP.encodeElement(this.receiptTrieRoot);
        byte[] logsBloom = RLP.encodeElement(this.logsBloom);
        byte[] difficulty = RLP.encodeElement(this.difficulty);
        byte[] extraData = RLP.encodeElement(this.extraData);
        byte[] energyConsumed = RLP.encodeBigInteger(BigInteger.valueOf(this.energyConsumed));
        byte[] energyLimit = RLP.encodeBigInteger(BigInteger.valueOf(this.energyLimit));

        byte[] timestamp = RLP.encodeBigInteger(BigInteger.valueOf(this.timestamp));

        byte[] seed = RLP.encodeElement(this.seed);

        if (withSignature) {
            byte[] signature = RLP.encodeElement(this.signature);
            return RLP.encodeList(
                    RLPversion,
                    number,
                    parentHash,
                    coinbase,
                    stateRoot,
                    txTrieRoot,
                    receiptTrieRoot,
                    logsBloom,
                    difficulty,
                    extraData,
                    energyConsumed,
                    energyLimit,
                    timestamp,
                    signature,
                    seed);
        } else {
            return RLP.encodeList(
                    RLPversion,
                    parentHash,
                    coinbase,
                    stateRoot,
                    txTrieRoot,
                    receiptTrieRoot,
                    logsBloom,
                    difficulty,
                    number,
                    timestamp,
                    extraData,
                    seed,
                    energyConsumed,
                    energyLimit);
        }
    }

    public String toString() {
        return toStringWithSuffix("\n");
    }

    private String toStringWithSuffix(final String suffix) {
        StringBuilder toStringBuff = new StringBuilder();
        toStringBuff
                .append("  hash=")
                .append(toHexString(getHash()))
                .append("  Length: ")
                .append(getHash().length)
                .append(suffix);
        toStringBuff
                .append("  version=")
                .append(Integer.toHexString(version))
                .append("  Length: ")
                .append(suffix);
        toStringBuff.append("  number=").append(number).append(suffix);
        toStringBuff
                .append("  parentHash=")
                .append(toHexString(parentHash))
                .append("  parentHash: ")
                .append(parentHash.length)
                .append(suffix);
        toStringBuff
                .append("  coinbase=")
                .append(coinbase.toString())
                .append("  coinBase: ")
                .append(coinbase.toByteArray().length)
                .append(suffix);
        toStringBuff
                .append("  stateRoot=")
                .append(toHexString(stateRoot))
                .append("  stateRoot: ")
                .append(stateRoot.length)
                .append(suffix);
        toStringBuff
                .append("  txTrieHash=")
                .append(toHexString(txTrieRoot))
                .append("  txTrieRoot: ")
                .append(txTrieRoot.length)
                .append(suffix);
        toStringBuff
                .append("  receiptsTrieHash=")
                .append(toHexString(receiptTrieRoot))
                .append("  receiptTrieRoot: ")
                .append(receiptTrieRoot.length)
                .append(suffix);
        toStringBuff
                .append("  difficulty=")
                .append(toHexString(difficulty))
                .append("  difficulty: ")
                .append(difficulty.length)
                .append(suffix);
        toStringBuff.append("  energyConsumed=").append(energyConsumed).append(suffix);
        toStringBuff.append("  energyLimit=").append(energyLimit).append(suffix);
        toStringBuff.append("  extraData=").append(toHexString(extraData)).append(suffix);
        toStringBuff
                .append("  timestamp=")
                .append(timestamp)
                .append(" (")
                .append(longToDateTime(timestamp))
                .append(")")
                .append(suffix);
        toStringBuff.append("  signature=").append(toHexString(signature)).append(suffix);
        toStringBuff.append("  seed=").append(toHexString(seed)).append(suffix);
        return toStringBuff.toString();
    }

    public String toFlatString() {
        return toStringWithSuffix("");
    }

    public byte[] getSeed() {
        return this.seed;
    }

    public void setSeed(byte[] seed) {
        this.seed = seed;
    }
    
    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public long getEnergyConsumed() {
        return this.energyConsumed;
    }

    public long getEnergyLimit() {
        return this.energyLimit;
    }

    /**
     * Set the energyConsumed field in header, this is used during block creation
     *
     * @param energyConsumed total energyConsumed during execution of transactions
     */
    public void setEnergyConsumed(long energyConsumed) {
        this.energyConsumed = energyConsumed;
    }

    /**
     * Return unencoded bytes of the header
     *
     * @param toStake Return header bytes excluding signature if true; else the entire block
     *     header
     * @return byte array containing raw header bytes
     */
    public byte[] getHeaderBytes(boolean toStake) {
        byte[] headerBytes;
        if (toStake) {
            headerBytes =
                    merge(
                            new byte[] {this.version},
                            longToBytes(this.number),
                            this.parentHash,
                            this.coinbase.toByteArray(),
                            this.stateRoot,
                            this.txTrieRoot,
                            this.receiptTrieRoot,
                            this.logsBloom,
                            this.difficulty,
                            this.extraData,
                            longToBytes(this.energyConsumed),
                            longToBytes(this.energyLimit),
                            longToBytes(this.timestamp),
                            this.seed);
        } else {
            headerBytes =
                    merge(
                            new byte[] {this.version},
                            longToBytes(this.number),
                            this.parentHash,
                            this.coinbase.toByteArray(),
                            this.stateRoot,
                            this.txTrieRoot,
                            this.receiptTrieRoot,
                            this.logsBloom,
                            this.difficulty,
                            this.extraData,
                            longToBytes(this.energyConsumed),
                            longToBytes(this.energyLimit),
                            longToBytes(this.timestamp),
                            this.signature,
                            this.seed);
        }
        return headerBytes;
    }

    /**
     * Get hash of the header bytes to mine a block
     *
     * @return Blake2b digest (32 bytes) of the raw header bytes.
     */
    public byte[] getMineHash() {
        if (this.mineHashBytes == null) {
            this.mineHashBytes = HashUtil.h256(getHeaderBytes(true));
        }
        return mineHashBytes;
    }

    public static StakedBlockHeader fromRLP(byte[] rawData, boolean isUnsafe) throws Exception {
        return fromRLP((RLPList) RLP.decode2(rawData).get(0), isUnsafe);
    }

    /**
     * Construct a block header from RLP
     *
     * @param rlpHeader
     * @param isUnsafe
     * @return
     */
    public static StakedBlockHeader fromRLP(RLPList rlpHeader, boolean isUnsafe) throws Exception {
        Builder builder = new Builder();
        if (isUnsafe) {
            builder.fromUnsafeSource();
        }

        // Version
        byte[] version = rlpHeader.get(RPL_BH_VERSION).getRLPData();
        if (version != null && version.length == 1) builder.withVersion(version[0]);

        // Number
        byte[] nrBytes = rlpHeader.get(RPL_BH_NUMBER).getRLPData();
        if (nrBytes != null) {
            builder.withNumber(nrBytes);
        }

        // Parent Hash
        builder.withParentHash(rlpHeader.get(RPL_BH_PARENTHASH).getRLPData());

        // Coinbase (miner)
        builder.withCoinbase(new AionAddress(rlpHeader.get(RPL_BH_COINBASE).getRLPData()));

        // State root
        builder.withStateRoot(rlpHeader.get(RPL_BH_STATEROOT).getRLPData());

        // TxTrie root
        byte[] txTrieRoot = rlpHeader.get(RPL_BH_TXTRIE).getRLPData();
        if (txTrieRoot != null) {
            builder.withTxTrieRoot(txTrieRoot);
        }

        // Receipt Trie root
        byte[] receiptTrieRoot = rlpHeader.get(RPL_BH_RECEIPTTRIE).getRLPData();
        if (receiptTrieRoot != null) {
            builder.withReceiptTrieRoot(receiptTrieRoot);
        }

        // LogsBloom
        builder.withLogsBloom(rlpHeader.get(RPL_BH_LOGSBLOOM).getRLPData());

        // Difficulty
        builder.withDifficulty(rlpHeader.get(RPL_BH_DIFFICULTY).getRLPData());

        // ExtraData
        builder.withExtraData(rlpHeader.get(RPL_BH_EXTRADATA).getRLPData());

        // Energy Consumed
        byte[] energyConsumedBytes = rlpHeader.get(RPL_BH_NRG_CONSUMED).getRLPData();
        if (energyConsumedBytes != null) {
            builder.withEnergyConsumed(energyConsumedBytes);
        }

        // Energy limit
        byte[] energyLimitBytes = rlpHeader.get(RPL_BH_NRG_LIMIT).getRLPData();
        if (energyLimitBytes != null) {
            builder.withEnergyLimit(energyLimitBytes);
        }

        // Timestamp
        byte[] tsBytes = rlpHeader.get(RPL_BH_TIMESTAMP).getRLPData();
        if (tsBytes != null) {
            builder.withTimestamp(tsBytes);
        }

        // Signature
        builder.withSignature(rlpHeader.get(RPL_BH_SIGNATURE).getRLPData());

        // Seed
        builder.withSeed(rlpHeader.get(RPL_BH_SEED).getRLPData());

        return builder.build();
    }

    /** Builder used to introduce blocks into system that come from unsafe sources */
    public static class Builder {

        /*
         * Some constants for fallbacks, these are not rigorously defined this;
         * TODO: define these with explanations in the future
         */

        protected byte version;
        protected byte[] parentHash;
        protected AionAddress coinbase;
        protected byte[] stateRoot;
        protected byte[] txTrieRoot;
        protected byte[] receiptTrieRoot;
        protected byte[] logsBloom;
        protected byte[] difficulty;
        protected long timestamp;
        protected long number;
        protected byte[] extraData;
        protected long energyConsumed;
        protected long energyLimit;
        protected byte[] seed;
        protected byte[] signature;

        /*
         * Builder parameters, not related to header data structure
         */
        protected boolean isFromUnsafeSource = false;
        private static int SIG_LENGTH = 64;
        private static byte[] EMPTY_SIGNATURE = new byte[64];
        private static byte[] EMPTY_BLOOM = new byte[256];

        /**
         * Indicates that the data is from an unsafe source
         *
         * @return {@code builder} same instance of builder
         */
        public Builder fromUnsafeSource() {
            isFromUnsafeSource = true;
            return this;
        }

        public Builder withVersion(byte version) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (version < 1) {
                    throw new HeaderStructureException(
                            "version", RPL_BH_VERSION, "must be greater than 0");
                }
            }

            this.version = version;
            return this;
        }

        public Builder withParentHash(byte[] parentHash) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (parentHash == null)
                    throw new HeaderStructureException(
                            "parentHash", RPL_BH_PARENTHASH, "cannot be null");

                if (parentHash.length != 32)
                    throw new HeaderStructureException(
                            "parentHash", RPL_BH_PARENTHASH, "must be of length 32");
            }

            this.parentHash = parentHash;
            return this;
        }

        public Builder withCoinbase(AionAddress coinbase) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (coinbase == null)
                    throw new HeaderStructureException(
                            "coinbase", RPL_BH_COINBASE, "cannot be null");
            }

            this.coinbase = coinbase;
            return this;
        }

        public Builder withStateRoot(byte[] stateRoot) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (stateRoot == null)
                    throw new HeaderStructureException(
                            "stateRoot", RPL_BH_STATEROOT, "cannot be null");

                if (stateRoot.length != 32)
                    throw new HeaderStructureException(
                            "stateRoot", RPL_BH_STATEROOT, "must be of length 32");
            }

            this.stateRoot = stateRoot;
            return this;
        }

        public Builder withTxTrieRoot(byte[] txTrieRoot) throws HeaderStructureException {
            if (isFromUnsafeSource) {

                if (txTrieRoot == null)
                    throw new HeaderStructureException(
                            "txTrieRoot", RPL_BH_TXTRIE, "cannot be null");

                if (txTrieRoot.length != 32)
                    throw new HeaderStructureException(
                            "txTrieRoot", RPL_BH_TXTRIE, "must be of length 32");
            }

            this.txTrieRoot = txTrieRoot;
            return this;
        }

        public Builder withReceiptTrieRoot(byte[] receiptTrieRoot) throws HeaderStructureException {
            if (isFromUnsafeSource) {

                if (receiptTrieRoot == null)
                    throw new HeaderStructureException(
                            "receiptTrieRoot", RPL_BH_RECEIPTTRIE, "cannot be null");

                if (receiptTrieRoot.length != 32)
                    throw new HeaderStructureException(
                            "receiptTrieRoot", RPL_BH_RECEIPTTRIE, "must be of length 32");
            }

            this.receiptTrieRoot = receiptTrieRoot;
            return this;
        }

        public Builder withLogsBloom(byte[] logsBloom) throws HeaderStructureException {
            if (isFromUnsafeSource) {

                if (logsBloom == null)
                    throw new HeaderStructureException(
                            "logsBloom", RPL_BH_LOGSBLOOM, "cannot be null");

                if (logsBloom.length != 256)
                    throw new HeaderStructureException(
                            "logsBloom", RPL_BH_LOGSBLOOM, "logsBloom must be of length 256");
            }

            this.logsBloom = logsBloom;
            return this;
        }

        public Builder withDifficulty(byte[] difficulty) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                Objects.requireNonNull(difficulty);
                if (difficulty.length > 16)
                    throw new HeaderStructureException(
                            "difficulty", RPL_BH_DIFFICULTY, "cannot be greater than 16 bytes");
            }
            this.difficulty = difficulty;
            return this;
        }

        public Builder withDifficulty(BigInteger difficulty) throws HeaderStructureException {
            return withDifficulty(ByteUtil.bigIntegerToBytes(difficulty));
        }

        public Builder withTimestamp(long timestamp) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (timestamp < 0)
                    throw new HeaderStructureException(
                            "timestamp", RPL_BH_TIMESTAMP, "must be positive value");
            }

            this.timestamp = timestamp;
            return this;
        }

        public Builder withTimestamp(byte[] timestamp) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                Objects.requireNonNull(timestamp);
                if (timestamp.length > 8)
                    throw new HeaderStructureException(
                            "timestamp", RPL_BH_TIMESTAMP, "cannot be greater than 8 bytes");
            }
            return withTimestamp(ByteUtil.byteArrayToLong(timestamp));
        }

        public Builder withNumber(long number) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (number < 0) {
                    throw new HeaderStructureException("number", RPL_BH_NUMBER, "must be positive");
                }
            }

            this.number = number;
            return this;
        }

        public Builder withNumber(byte[] number) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (number == null)
                    throw new HeaderStructureException("number", RPL_BH_NUMBER, "cannot be null");
            }
            return withNumber(ByteUtil.byteArrayToLong(number));
        }

        public Builder withExtraData(byte[] extraData) throws HeaderStructureException {
            if (isFromUnsafeSource) {

                if (extraData == null)
                    throw new HeaderStructureException(
                            "extraData", RPL_BH_EXTRADATA, "cannot be null");

                if (extraData.length > 32) {
                    throw new HeaderStructureException(
                            "extraData", RPL_BH_EXTRADATA, "cannot be greater than 32 bytes");
                }
            }

            this.extraData = extraData;
            return this;
        }

        public Builder withEnergyConsumed(long energyConsumed) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (energyConsumed < 0) {
                    throw new HeaderStructureException(
                            "energyConsumed", RPL_BH_NRG_CONSUMED, "must be positive value");
                }
            }

            this.energyConsumed = energyConsumed;
            return this;
        }

        public Builder withEnergyConsumed(byte[] energyConsumed) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (energyConsumed == null)
                    throw new HeaderStructureException(
                            "energyConsumed", RPL_BH_NRG_CONSUMED, "cannot be null");

                if (energyConsumed.length > 8)
                    throw new HeaderStructureException(
                            "energyConsumed",
                            RPL_BH_NRG_CONSUMED,
                            "cannot be greater than 8 bytes");
            }

            return withEnergyConsumed(ByteUtil.byteArrayToLong(energyConsumed));
        }

        public Builder withEnergyLimit(long energyLimit) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (energyLimit < 0) {
                    throw new HeaderStructureException(
                            "energyLimitException",
                            RPL_BH_NRG_LIMIT,
                            "energyLimit must be positive value");
                }
            }

            this.energyLimit = energyLimit;
            return this;
        }

        public Builder withEnergyLimit(byte[] energyLimit) throws HeaderStructureException {
            if (isFromUnsafeSource) {

                if (energyLimit == null)
                    throw new HeaderStructureException(
                            "energyLimit", RPL_BH_NRG_LIMIT, "cannot be null");

                if (energyLimit.length > 8)
                    throw new HeaderStructureException(
                            "energyLimit",
                            RPL_BH_NRG_LIMIT,
                            "energyLimit cannot be greater than 8 bytes");
            }
            return withEnergyLimit(ByteUtil.byteArrayToLong(energyLimit));
        }

        public Builder withSeed(byte[] seed) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (seed == null)
                    throw new HeaderStructureException(
                            "seed", RPL_BH_SEED, "cannot be null");

                if (seed.length != SIG_LENGTH) {
                    throw new HeaderStructureException(
                            "seed", RPL_BH_SEED, "invalid seed length");
                }
            }
            this.seed = seed;
            return this;
        }

        public Builder withSignature(byte[] signature) throws HeaderStructureException {
            if (isFromUnsafeSource) {
                if (signature == null)
                    throw new HeaderStructureException("signature", RPL_BH_SIGNATURE, "cannot be null");
                
                // TODO: Maybe let this be empty so that stakers can use it to create pre-signed blocks?
                if (signature.length != SIG_LENGTH) {
                    throw new HeaderStructureException(
                            "signature", RPL_BH_SIGNATURE, "invalid signature length");
                }
            }

            this.signature = signature;
            return this;
        }

        public StakedBlockHeader build() {

            this.version = this.version == 0 ? 1 : this.version;
            this.parentHash = this.parentHash == null ? HashUtil.EMPTY_DATA_HASH : this.parentHash;
            this.coinbase = this.coinbase == null ? AddressUtils.ZERO_ADDRESS : this.coinbase;
            this.stateRoot = this.stateRoot == null ? HashUtil.EMPTY_TRIE_HASH : this.stateRoot;
            this.txTrieRoot = this.txTrieRoot == null ? HashUtil.EMPTY_TRIE_HASH : this.txTrieRoot;
            this.receiptTrieRoot =
                    this.receiptTrieRoot == null ? HashUtil.EMPTY_TRIE_HASH : this.receiptTrieRoot;
            this.logsBloom = this.logsBloom == null ? EMPTY_BLOOM : this.logsBloom;
            this.difficulty = this.difficulty == null ? ByteUtil.EMPTY_HALFWORD : this.difficulty;
            this.extraData = this.extraData == null ? ByteUtil.EMPTY_WORD : this.extraData;
            this.signature = this.signature == null ? EMPTY_SIGNATURE : this.signature;
            this.seed = this.seed == null ? EMPTY_SIGNATURE : this.seed;

            StakedBlockHeader header =
                    new StakedBlockHeader(
                            this.version,
                            this.number,
                            this.parentHash,
                            this.coinbase,
                            this.logsBloom,
                            this.difficulty,
                            this.extraData,
                            this.energyConsumed,
                            this.energyLimit,
                            this.timestamp,
                            this.signature,
                            this.seed);
            header.setReceiptsRoot(this.receiptTrieRoot);
            header.setStateRoot(this.stateRoot);
            header.txTrieRoot = this.txTrieRoot;
            return header;
        }
    }
}
