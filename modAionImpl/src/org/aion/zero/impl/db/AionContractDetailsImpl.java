package org.aion.zero.impl.db;

import static org.aion.crypto.HashUtil.EMPTY_LIST_HASH;
import static org.aion.crypto.HashUtil.EMPTY_TRIE_HASH;
import static org.aion.crypto.HashUtil.h256;
import static org.aion.types.ByteArrayWrapper.wrap;
import static org.aion.util.bytes.ByteUtil.EMPTY_BYTE_ARRAY;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
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

    private ByteArrayKeyValueStore dataSource;

    private byte[] rlpEncoded;

    private Address address;

    private SecureTrie storageTrie = new SecureTrie(null);

    public boolean externalStorage;
    private ByteArrayKeyValueStore externalStorageDataSource;

    protected byte[] objectGraphHash = EMPTY_LIST_HASH;

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

    /**
     * Returns the storage hash.
     *
     * @return the storage hash.
     */
    @Override
    public byte[] getStorageHash() {
        if (vmType == TransactionTypes.AVM_CREATE_CODE) {
            // todo: store the result
            byte[] a = storageTrie.getRootHash();
            byte[] b = objectGraphHash;
            byte[] c = new byte[a.length + b.length];
            System.arraycopy(a, 0, c, 0, a.length);
            System.arraycopy(b, 0, c, a.length, b.length);
            return h256(c);
        } else {
            return storageTrie.getRootHash();
        }
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
            decodeFvmPreFork(rlpList, fastCheck);

            // only FVM contracts used the old encoding
            vmType = TransactionTypes.FVM_CREATE_CODE;

            // save with new encoding
            this.rlpEncoded = null;
            getEncoded();
        } else {
            // compatible with new encoding
            decodePostFork(rlpList, fastCheck);

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
    public void decodeFvmPreFork(RLPList rlpList, boolean fastCheck) {
        RLPItem isExternalStorage = (RLPItem) rlpList.get(1);
        RLPItem storage = (RLPItem) rlpList.get(3);
        this.externalStorage = isExternalStorage.getRLPData().length > 0;
        boolean keepStorageInMem = storage.getRLPData().length <= detailsInMemoryStorageLimit;

        // No externalStorage require.
        if (fastCheck && !externalStorage && keepStorageInMem) {
            return;
        }

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
     * <p>The encoding is a list of 6 elements for FVM contracts:<br>
     * { address, vmType, isExternalStorage, storageRoot, storage, code }
     *
     * <p>The encoding is a list of 7 elements for AVM contracts:<br>
     * { address, vmType, isExternalStorage, storageRoot, storage, code, objectGraphHash }
     */
    public void decodePostFork(RLPList rlpList, boolean fastCheck) {
        RLPItem isExternalStorage = (RLPItem) rlpList.get(2);
        RLPItem storage = (RLPItem) rlpList.get(4);
        this.externalStorage = isExternalStorage.getRLPData().length > 0;
        boolean keepStorageInMem = storage.getRLPData().length <= detailsInMemoryStorageLimit;

        // No externalStorage require.
        if (fastCheck && !externalStorage && keepStorageInMem) {
            return;
        }

        RLPItem address = (RLPItem) rlpList.get(0);
        RLPItem vm = (RLPItem) rlpList.get(1);
        RLPItem storageRoot = (RLPItem) rlpList.get(3);
        RLPElement code = rlpList.get(5);

        if (address == null
                || address.getRLPData() == null
                || address.getRLPData().length != Address.SIZE) {
            throw new IllegalArgumentException("rlp decode error: invalid contract address");
        } else {
            this.address = Address.wrap(address.getRLPData());
        }

        if (vm == null || vm.getRLPData() == null || vm.getRLPData().length != 1) {
            throw new IllegalArgumentException("rlp decode error: invalid vm code");
        } else {
            this.vmType = vm.getRLPData()[0];
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

        // get object graph hash only for AVM
        if (vmType == TransactionTypes.AVM_CREATE_CODE) {
            RLPItem graphHash = (RLPItem) rlpList.get(6);
            if (graphHash == null
                    || graphHash.getRLPData() == null
                    || graphHash.getRLPData().length != 32) {
                throw new IllegalArgumentException("rlp decode error: invalid object graph hash");
            } else {
                this.objectGraphHash = graphHash.getRLPData();
            }
        }
    }

    /**
     * Returns an rlp encoding of this AionContractDetailsImpl object.
     *
     * @return an rlp encoding of this.
     */
    @Override
    public byte[] getEncoded() {
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
     * { address, vmType, isExternalStorage, storageRoot, storage, code }
     *
     * <p>The encoding is a list of 7 elements for AVM contracts:<br>
     * { address, vmType, isExternalStorage, storageRoot, storage, code, objectGraphHash }
     *
     * @return an rlp encoding of this object
     */
    public byte[] getEncodedPostFork() {
        if (rlpEncoded == null) {

            byte[] rlpAddress = RLP.encodeElement(address.toBytes());
            byte[] rlpVmType = RLP.encodeByte(vmType);
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

            if (vmType == TransactionTypes.FVM_CREATE_CODE) {
                this.rlpEncoded =
                        RLP.encodeList(
                                rlpAddress,
                                rlpVmType,
                                rlpIsExternalStorage,
                                rlpStorageRoot,
                                rlpStorage,
                                rlpCode);
            } else if (vmType == TransactionTypes.AVM_CREATE_CODE) {
                // storing also the object graph for the AVM
                byte[] rlpObjectGraphHash = RLP.encodeElement(objectGraphHash);
                this.rlpEncoded =
                        RLP.encodeList(
                                rlpAddress,
                                rlpVmType,
                                rlpIsExternalStorage,
                                rlpStorageRoot,
                                rlpStorage,
                                rlpCode,
                                rlpObjectGraphHash);
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
     * Sets the external storage data source to dataSource.
     *
     * @param dataSource The new data source.
     */
    public void setExternalStorageDataSource(ByteArrayKeyValueStore dataSource) {
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
        details.externalStorage = this.externalStorage;
        details.externalStorageDataSource = this.externalStorageDataSource;
        details.dataSource = dataSource;

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
        aionContractDetailsCopy.dataSource = this.dataSource;
        aionContractDetailsCopy.externalStorageDataSource = this.externalStorageDataSource;
        aionContractDetailsCopy.externalStorage = this.externalStorage;
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
