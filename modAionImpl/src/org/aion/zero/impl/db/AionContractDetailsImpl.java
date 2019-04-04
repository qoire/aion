package org.aion.zero.impl.db;

import static org.aion.crypto.HashUtil.EMPTY_DATA_HASH;
import static org.aion.crypto.HashUtil.EMPTY_TRIE_HASH;
import static org.aion.crypto.HashUtil.h256;
import static org.aion.types.ByteArrayWrapper.wrap;
import static org.aion.util.bytes.ByteUtil.EMPTY_BYTE_ARRAY;

import com.google.common.annotations.VisibleForTesting;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import org.aion.interfaces.db.ByteArrayKeyValueStore;
import org.aion.interfaces.db.ContractDetails;
import org.aion.mcf.ds.XorDataSource;
import org.aion.mcf.trie.SecureTrie;
import org.aion.mcf.tx.TransactionTypes;
import org.aion.rlp.RLP;
import org.aion.rlp.RLPElement;
import org.aion.rlp.RLPItem;
import org.aion.rlp.RLPList;
import org.aion.types.Address;
import org.aion.types.ByteArrayWrapper;

public class AionContractDetailsImpl extends AbstractContractDetails {
    private static final int HASH_SIZE = 32;

    private ByteArrayKeyValueStore dataSource;
    private ByteArrayKeyValueStore objectGraphSource = null;

    private byte[] rlpEncoded;

    private Address address;

    private SecureTrie storageTrie = new SecureTrie(null);

    public boolean externalStorage;
    private ByteArrayKeyValueStore externalStorageDataSource;
    private ByteArrayKeyValueStore contractObjectGraphSource = null;

    private byte[] objectGraphHash = EMPTY_DATA_HASH;
    private byte[] concatenatedStorageHash = EMPTY_DATA_HASH;

    public AionContractDetailsImpl() {}

    public AionContractDetailsImpl(int prune, int memStorageLimit) {
        super(prune, memStorageLimit);
    }

    private AionContractDetailsImpl(
            Address address, SecureTrie storageTrie, Map<ByteArrayWrapper, byte[]> codes) {
        if (address == null) {
            throw new IllegalArgumentException("Address can not be null!");
        } else {
            this.address = address;
        }
        this.storageTrie = storageTrie;
        setCodes(codes);
    }

    public AionContractDetailsImpl(byte[] code) throws Exception {
        if (code == null) {
            throw new Exception("Empty input code");
        }

        decode(code);
    }

    /**
     * Adds the key-value pair to the database unless value is an ByteArrayWrapper whose underlying
     * byte array consists only of zeros. In this case, if key already exists in the database it
     * will be deleted.
     *
     * @param key The key.
     * @param value The value.
     */
    @Override
    public void put(ByteArrayWrapper key, ByteArrayWrapper value) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(value);

        // The following must be done before making this call:
        // We strip leading zeros of a DataWordImpl but not a DoubleDataWord so that when we call
        // get we can differentiate between the two.

        byte[] data = RLP.encodeElement(value.getData());
        storageTrie.update(key.getData(), data);

        this.setDirty(true);
        this.rlpEncoded = null;
    }

    @Override
    public void delete(ByteArrayWrapper key) {
        Objects.requireNonNull(key);

        storageTrie.delete(key.getData());

        this.setDirty(true);
        this.rlpEncoded = null;
    }

    /**
     * Returns the value associated with key if it exists, otherwise returns a DataWordImpl
     * consisting entirely of zero bytes.
     *
     * @param key The key to query.
     * @return the corresponding value or a zero-byte DataWordImpl if no such value.
     */
    @Override
    public ByteArrayWrapper get(ByteArrayWrapper key) {
        byte[] data = storageTrie.get(key.getData());
        return (data == null || data.length == 0)
                ? null
                : new ByteArrayWrapper(RLP.decode2(data).get(0).getRLPData());
    }

    public byte getVmType() {
        return vmType;
    }

    @Override
    public byte[] getObjectGraph() {
        if (objectGraph == null) {
            // the object graph was not stored yet
            if (java.util.Arrays.equals(objectGraphHash, EMPTY_DATA_HASH)) {
                return EMPTY_BYTE_ARRAY;
            } else {
                // note: the enforced use of optional is rather cumbersome here
                Optional<byte[]> dbVal = getContractObjectGraphSource().get(objectGraphHash);
                objectGraph = dbVal.isPresent() ? dbVal.get() : null;
            }
        }
        return objectGraph == null ? EMPTY_BYTE_ARRAY : objectGraph;
    }

    @Override
    public void setObjectGraph(byte[] graph) {
        Objects.requireNonNull(graph);

        this.objectGraph = graph;
        this.objectGraphHash = h256(objectGraph);

        this.setDirty(true);
        this.rlpEncoded = null;
    }

    // TODO: use until the AVM impl is added
    private final boolean enableObjectGraph = false;

    /**
     * Returns the storage hash.
     *
     * @return the storage hash.
     */
    @Override
    public byte[] getStorageHash() {
        if (enableObjectGraph && vmType == TransactionTypes.AVM_CREATE_CODE) {
            return computeAvmStorageHash();
        } else {
            return storageTrie.getRootHash();
        }
    }

    private byte[] computeAvmStorageHash() {
        byte[] storageRoot = storageTrie.getRootHash();
        byte[] graphHash = getObjectGraph();
        byte[] concatenated = new byte[storageRoot.length + graphHash.length];
        System.arraycopy(storageRoot, 0, concatenated, 0, storageRoot.length);
        System.arraycopy(graphHash, 0, concatenated, storageRoot.length, graphHash.length);
        return h256(concatenated);
    }

    /**
     * Decodes an AionContractDetailsImpl object from the RLP encoding rlpCode.
     *
     * @param rlpCode The encoding to decode.
     */
    @Override
    public void decode(byte[] rlpCode) {
        decode(rlpCode, false);
    }

    /**
     * Decodes an AionContractDetailsImpl object from the RLP encoding rlpCode with fast check does
     * the contractDetails needs external storage.
     *
     * @param rlpCode The encoding to decode.
     * @param fastCheck set fastCheck option.
     */
    @Override
    public void decode(byte[] rlpCode, boolean fastCheck) {
        RLPList data = RLP.decode2(rlpCode);

        RLPList rlpList = (RLPList) data.get(0);

        if (rlpList.size() == 5) {
            // compatible with old encoding
            decodeOldFvmEncoding(rlpList);

            // only FVM contracts used the old encoding
            vmType = TransactionTypes.FVM_CREATE_CODE;

            // save with new encoding
            this.rlpEncoded = null;
            getEncoded();
        } else {
            // compatible with new encoding
            decodeNewEncoding(rlpList);

            // compatible with new encoding that differentiates encoding based on VM used
            this.rlpEncoded = rlpCode;
        }
    }

    /**
     * Decodes the old version of encoding which was a list of 5 elements, specifically:<br>
     * { address, isExternalStorage, storageRoot, storage, code }
     *
     * <p>Only FVM contracts used this encoding on the <b>mainnet</b> and <b>mastery</b> networks.
     */
    public void decodeOldFvmEncoding(RLPList rlpList) {
        RLPItem isExternalStorage = (RLPItem) rlpList.get(1);
        RLPItem storage = (RLPItem) rlpList.get(3);
        this.externalStorage = isExternalStorage.getRLPData().length > 0;
        boolean keepStorageInMem = false; // to enforce switch to external storage

        RLPItem address = (RLPItem) rlpList.get(0);
        RLPItem storageRoot = (RLPItem) rlpList.get(2);
        RLPElement code = rlpList.get(4);

        if (address == null
                || address.getRLPData() == null
                || address.getRLPData().length != Address.SIZE) {
            throw new IllegalArgumentException("rlp decode error.");
        } else {
            this.address = Address.wrap(address.getRLPData());
        }

        if (code instanceof RLPList) {
            for (RLPElement e : ((RLPList) code)) {
                setCode(e.getRLPData());
            }
        } else {
            setCode(code.getRLPData());
        }

        // load/deserialize storage trie
        if (externalStorage) {
            storageTrie = new SecureTrie(getExternalStorageDataSource(), storageRoot.getRLPData());
        } else {
            storageTrie.deserialize(storage.getRLPData());
        }
        storageTrie.withPruningEnabled(prune > 0);

        // switch from in-memory to external storage
        if (!externalStorage && !keepStorageInMem) {
            externalStorage = true;
            storageTrie.getCache().setDB(getExternalStorageDataSource());
        }
    }

    /**
     * Decodes the new version of encoding.
     *
     * <p>The encoding is a list of 4 elements for FVM contracts:<br>
     * { 0:address, 1:vmType, 2:code, 3:storageRoot }
     *
     * <p>The encoding is a list of 6 elements for AVM contracts:<br>
     * { 0:address, 1:vmType, 2:code, 3:concatenatedStorageHash, 4:objectGraphHash, 5:storageRoot }
     */
    public void decodeNewEncoding(RLPList rlpList) {
        // always use external storage after transition to new encoding
        this.externalStorage = true;

        RLPItem address = (RLPItem) rlpList.get(0);
        RLPItem vm = (RLPItem) rlpList.get(1);
        RLPElement code = rlpList.get(2);

        // decode address
        if (address == null
                || address.getRLPData() == null
                || address.getRLPData().length != Address.SIZE) {
            throw new IllegalArgumentException("rlp decode error: invalid contract address");
        } else {
            this.address = Address.wrap(address.getRLPData());
        }

        // decode VM type
        if (vm == null || vm.getRLPData() == null || vm.getRLPData().length != 1) {
            throw new IllegalArgumentException("rlp decode error: invalid vm code");
        } else {
            this.vmType = vm.getRLPData()[0];
        }

        // decode code
        if (code instanceof RLPList) {
            for (RLPElement e : ((RLPList) code)) {
                setCode(e.getRLPData());
            }
        } else {
            setCode(code.getRLPData());
        }

        if (rlpList.size() == 4) { // FVM contract encoding
            // sanity check
            if (vmType != TransactionTypes.FVM_CREATE_CODE) {
                throw new IllegalArgumentException(
                        "rlp decode error: encoding size 4 is used only by fvm");
            }

            // decode FVM storage root
            RLPItem storageRoot = (RLPItem) rlpList.get(3);
            if (storageRoot == null
                    || storageRoot.getRLPData() == null
                    || (storageRoot.getRLPData().length != HASH_SIZE // must be a hash or empty
                            && storageRoot.getRLPData().length != 0)) {
                throw new IllegalArgumentException("rlp decode error: invalid FVM storage root");
            } else {
                storageTrie =
                        new SecureTrie(getExternalStorageDataSource(), storageRoot.getRLPData());
                storageTrie.withPruningEnabled(prune > 0);
            }
        } else if (rlpList.size() == 6) { // AVM contract encoding
            // sanity check
            if (vmType != TransactionTypes.AVM_CREATE_CODE) {
                throw new IllegalArgumentException(
                        "rlp decode error: encoding size 6 is used only by avm");
            }

            // decode AVM concatenated storage hash
            RLPItem concatHash = (RLPItem) rlpList.get(3);
            if (concatHash == null
                    || concatHash.getRLPData() == null
                    || concatHash.getRLPData().length != HASH_SIZE) {
                throw new IllegalArgumentException(
                        "rlp decode error: invalid AVM concatenated storage hash");
            } else {
                this.concatenatedStorageHash = concatHash.getRLPData();
            }

            // decode AVM object graph hash
            RLPItem graphHash = (RLPItem) rlpList.get(4);
            if (graphHash == null
                    || graphHash.getRLPData() == null
                    || graphHash.getRLPData().length != HASH_SIZE) {
                throw new IllegalArgumentException(
                        "rlp decode error: invalid AVM object graph hash");
            } else {
                this.objectGraphHash = graphHash.getRLPData();
            }

            // decode AVM storage root
            RLPItem storageRoot = (RLPItem) rlpList.get(5);
            if (storageRoot == null
                    || storageRoot.getRLPData() == null
                    || storageRoot.getRLPData().length != HASH_SIZE) {
                throw new IllegalArgumentException("rlp decode error: invalid FVM storage root");
            } else {
                storageTrie =
                        new SecureTrie(getExternalStorageDataSource(), storageRoot.getRLPData());
                storageTrie.withPruningEnabled(prune > 0);
            }
        } else {
            throw new IllegalArgumentException("rlp decode error: invalid encoded list size");
        }
    }

    /**
     * Returns an rlp encoding of this AionContractDetailsImpl object.
     *
     * @return an rlp encoding of this.
     */
    public byte[] getEncodedOld() {
        if (rlpEncoded == null) {

            byte[] rlpAddress = RLP.encodeElement(address.toBytes());
            byte[] rlpIsExternalStorage = RLP.encodeByte((byte) (externalStorage ? 1 : 0));
            byte[] rlpStorageRoot =
                    RLP.encodeElement(
                            externalStorage ? storageTrie.getRootHash() : EMPTY_BYTE_ARRAY);
            byte[] rlpStorage =
                    RLP.encodeElement(externalStorage ? EMPTY_BYTE_ARRAY : storageTrie.serialize());
            byte[][] codes = new byte[getCodes().size()][];
            int i = 0;
            for (byte[] bytes : this.getCodes().values()) {
                codes[i++] = RLP.encodeElement(bytes);
            }
            byte[] rlpCode = RLP.encodeList(codes);

            this.rlpEncoded =
                    RLP.encodeList(
                            rlpAddress, rlpIsExternalStorage, rlpStorageRoot, rlpStorage, rlpCode);
        }

        return rlpEncoded;
    }

    /**
     * Returns an rlp encoding of this AionContractDetailsImpl object.
     *
     * <p>The encoding is a list of 6 elements for FVM contracts:<br>
     * { address, vmType, code, isExternalStorage, storageRoot, storage }
     *
     * <p>The encoding is a list of 7 elements for AVM contracts:<br>
     * { address, vmType, code, concatenatedStorageHash, objectGraphHash, storageRoot }
     *
     * @return an rlp encoding of this object
     */
    @Override
    public byte[] getEncoded() {
        if (rlpEncoded == null) {

            byte[] rlpAddress = RLP.encodeElement(address.toBytes());
            byte[] rlpVmType = RLP.encodeByte(vmType);
            byte[] rlpStorageRoot =
                    RLP.encodeElement(
                            externalStorage ? storageTrie.getRootHash() : EMPTY_BYTE_ARRAY);
            byte[][] codes = new byte[getCodes().size()][];
            int i = 0;
            for (byte[] bytes : this.getCodes().values()) {
                codes[i++] = RLP.encodeElement(bytes);
            }
            byte[] rlpCode = RLP.encodeList(codes);

            if (vmType == TransactionTypes.AVM_CREATE_CODE) {
                // storing also the object graph for the AVM
                byte[] rlpObjectGraphHash = RLP.encodeElement(objectGraphHash);
                byte[] rlpConcatenatedStorageHash = RLP.encodeElement(concatenatedStorageHash);

                this.rlpEncoded =
                        RLP.encodeList(
                                rlpAddress,
                                rlpVmType,
                                rlpCode,
                                rlpConcatenatedStorageHash,
                                rlpObjectGraphHash,
                                rlpStorageRoot);
            } else {
                if (vmType != TransactionTypes.FVM_CREATE_CODE) {
                    // for precompiled contracts
                    vmType = TransactionTypes.FVM_CREATE_CODE;
                    rlpVmType = RLP.encodeByte(vmType);
                }
                this.rlpEncoded = RLP.encodeList(rlpAddress, rlpVmType, rlpCode, rlpStorageRoot);
            }
        }

        // the encoding will be null when the VM code is not set to one of the two allowed VMs
        return rlpEncoded;
    }

    /**
     * Get the address associated with this AionContractDetailsImpl.
     *
     * @return the associated address.
     */
    @Override
    public Address getAddress() {
        return address;
    }

    /**
     * Sets the associated address to address.
     *
     * @param address The address to set.
     */
    @Override
    public void setAddress(Address address) {
        if (address == null) {
            throw new IllegalArgumentException("Address can not be null!");
        }
        this.address = address;
        this.rlpEncoded = null;
    }

    /** Syncs the storage trie. */
    @Override
    public void syncStorage() {
        if (vmType == TransactionTypes.AVM_CREATE_CODE) {
            if (objectGraph == null || Arrays.equals(objectGraphHash, EMPTY_DATA_HASH)) {
                throw new IllegalStateException(
                        "The AVM object graph must be set before pushing data to disk.");
            }
            getContractObjectGraphSource().put(objectGraphHash, objectGraph);
            getContractObjectGraphSource()
                    .put(
                            computeAvmStorageHash(),
                            RLP.encodeList(
                                    RLP.encodeElement(storageTrie.getRootHash()),
                                    RLP.encodeElement(getObjectGraph())));
        }

        if (externalStorage) {
            storageTrie.sync();
        }
    }

    /**
     * Sets the data source to dataSource.
     *
     * @param dataSource The new dataSource.
     */
    public void setDataSource(ByteArrayKeyValueStore dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void setObjectGraphSource(ByteArrayKeyValueStore objectGraphSource) {
        this.objectGraphSource = objectGraphSource;
    }

    /**
     * Returns the external storage data source.
     *
     * @return the external storage data source.
     */
    private ByteArrayKeyValueStore getExternalStorageDataSource() {
        if (externalStorageDataSource == null) {
            externalStorageDataSource =
                    new XorDataSource(
                            dataSource, h256(("details-storage/" + address.toString()).getBytes()));
        }
        return externalStorageDataSource;
    }

    /**
     * Returns the data source specific to the current contract.
     *
     * @return the data source specific to the current contract.
     */
    private ByteArrayKeyValueStore getContractObjectGraphSource() {
        if (contractObjectGraphSource == null) {
            contractObjectGraphSource =
                    new XorDataSource(
                            objectGraphSource,
                            h256(("details-graph/" + address.toString()).getBytes()));
        }
        return contractObjectGraphSource;
    }

    /**
     * Sets the external storage data source to dataSource.
     *
     * @param dataSource The new data source.
     * @implNote The tests are taking a shortcut here in bypassing the XorDataSource created by
     *     {@link #getExternalStorageDataSource()}. Do not use this method in production.
     */
    @VisibleForTesting
    void setExternalStorageDataSource(ByteArrayKeyValueStore dataSource) {
        // TODO: regarding the node above: the tests should be updated and the method removed
        this.externalStorageDataSource = dataSource;
        this.externalStorage = true;
        this.storageTrie = new SecureTrie(getExternalStorageDataSource());
    }

    /**
     * Returns an AionContractDetailsImpl object pertaining to a specific point in time given by the
     * root hash hash.
     *
     * @param hash The root hash to search for.
     * @return the specified AionContractDetailsImpl.
     */
    @Override
    public ContractDetails getSnapshotTo(byte[] hash) {

        SecureTrie snapStorage =
                wrap(hash).equals(wrap(EMPTY_TRIE_HASH))
                        ? new SecureTrie(storageTrie.getCache(), "".getBytes())
                        : new SecureTrie(storageTrie.getCache(), hash);
        snapStorage.withPruningEnabled(storageTrie.isPruningEnabled());

        AionContractDetailsImpl details =
                new AionContractDetailsImpl(this.address, snapStorage, getCodes());

        // vm information
        details.vmType = this.vmType;

        // storage information
        details.externalStorage = this.externalStorage;
        details.externalStorageDataSource = this.externalStorageDataSource;
        details.dataSource = dataSource;

        // object graph information
        details.objectGraphSource = this.objectGraphSource;
        details.contractObjectGraphSource = this.contractObjectGraphSource;
        details.objectGraph =
                objectGraph == null
                        ? null
                        : Arrays.copyOf(this.objectGraph, this.objectGraph.length);
        details.objectGraphHash =
                Arrays.equals(objectGraphHash, EMPTY_DATA_HASH)
                        ? EMPTY_DATA_HASH
                        : Arrays.copyOf(this.objectGraphHash, this.objectGraphHash.length);

        // storage hash used by AVM
        details.concatenatedStorageHash =
                Arrays.equals(concatenatedStorageHash, EMPTY_DATA_HASH)
                        ? EMPTY_DATA_HASH
                        : Arrays.copyOf(
                                this.concatenatedStorageHash, this.concatenatedStorageHash.length);

        return details;
    }

    /**
     * Returns a sufficiently deep copy of this contract details object.
     *
     * <p>The copy is not completely deep. The following object references will be passed on from
     * this object to the copy:
     *
     * <p>- The external storage data source: the copy will back-end on this same source. - The
     * previous root of the trie will pass its original object reference if this root is not of type
     * {@code byte[]}. - The current root of the trie will pass its original object reference if
     * this root is not of type {@code byte[]}. - Each {@link org.aion.rlp.Value} object reference
     * held by each of the {@link org.aion.mcf.trie.Node} objects in the underlying cache.
     *
     * @return A copy of this object.
     */
    @Override
    public AionContractDetailsImpl copy() {
        AionContractDetailsImpl aionContractDetailsCopy = new AionContractDetailsImpl();

        // vm information
        aionContractDetailsCopy.vmType = this.vmType;

        // storage information
        aionContractDetailsCopy.dataSource = this.dataSource;
        aionContractDetailsCopy.externalStorageDataSource = this.externalStorageDataSource;
        aionContractDetailsCopy.externalStorage = this.externalStorage;

        // object graph information
        aionContractDetailsCopy.objectGraphSource = this.objectGraphSource;
        aionContractDetailsCopy.contractObjectGraphSource = this.contractObjectGraphSource;
        aionContractDetailsCopy.objectGraph =
                objectGraph == null
                        ? null
                        : Arrays.copyOf(this.objectGraph, this.objectGraph.length);
        aionContractDetailsCopy.objectGraphHash =
                Arrays.equals(objectGraphHash, EMPTY_DATA_HASH)
                        ? EMPTY_DATA_HASH
                        : Arrays.copyOf(this.objectGraphHash, this.objectGraphHash.length);

        // storage hash used by AVM
        aionContractDetailsCopy.concatenatedStorageHash =
                Arrays.equals(concatenatedStorageHash, EMPTY_DATA_HASH)
                        ? EMPTY_DATA_HASH
                        : Arrays.copyOf(
                                this.concatenatedStorageHash, this.concatenatedStorageHash.length);

        aionContractDetailsCopy.prune = this.prune;
        aionContractDetailsCopy.detailsInMemoryStorageLimit = this.detailsInMemoryStorageLimit;
        aionContractDetailsCopy.setCodes(getDeepCopyOfCodes());
        aionContractDetailsCopy.setDirty(this.isDirty());
        aionContractDetailsCopy.setDeleted(this.isDeleted());
        aionContractDetailsCopy.address = new Address(this.address.toBytes());
        aionContractDetailsCopy.rlpEncoded =
                (this.rlpEncoded == null)
                        ? null
                        : Arrays.copyOf(this.rlpEncoded, this.rlpEncoded.length);
        aionContractDetailsCopy.storageTrie =
                (this.storageTrie == null) ? null : this.storageTrie.copy();
        return aionContractDetailsCopy;
    }

    // TODO: move this method up to the parent class.
    private Map<ByteArrayWrapper, byte[]> getDeepCopyOfCodes() {
        Map<ByteArrayWrapper, byte[]> originalCodes = this.getCodes();

        if (originalCodes == null) {
            return null;
        }

        Map<ByteArrayWrapper, byte[]> copyOfCodes = new HashMap<>();
        for (Entry<ByteArrayWrapper, byte[]> codeEntry : originalCodes.entrySet()) {

            ByteArrayWrapper keyWrapper = null;
            if (codeEntry.getKey() != null) {
                byte[] keyBytes = codeEntry.getKey().getData();
                keyWrapper = new ByteArrayWrapper(Arrays.copyOf(keyBytes, keyBytes.length));
            }

            byte[] copyOfValue =
                    (codeEntry.getValue() == null)
                            ? null
                            : Arrays.copyOf(codeEntry.getValue(), codeEntry.getValue().length);
            copyOfCodes.put(keyWrapper, copyOfValue);
        }
        return copyOfCodes;
    }
}
