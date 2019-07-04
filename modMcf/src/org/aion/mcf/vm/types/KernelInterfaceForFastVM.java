package org.aion.mcf.vm.types;

import com.google.common.annotations.VisibleForTesting;
import java.math.BigInteger;
import org.aion.mcf.core.AccountState;
import org.aion.mcf.db.IBlockStoreBase;
import org.aion.mcf.db.InternalVmType;
import org.aion.mcf.db.RepositoryCache;
import org.aion.mcf.types.KernelInterface;
import org.aion.mcf.valid.TxNrgRule;
import org.aion.mcf.vm.DataWord;
import org.aion.types.AionAddress;
import org.aion.vm.api.types.ByteArrayWrapper;

public class KernelInterfaceForFastVM implements KernelInterface {
    private RepositoryCache<AccountState, IBlockStoreBase<?, ?>> repositoryCache;
    private boolean allowNonceIncrement, isLocalCall;
    private boolean fork040Enable;

    @VisibleForTesting
    public KernelInterfaceForFastVM(
            RepositoryCache<AccountState, IBlockStoreBase<?, ?>> repositoryCache,
            boolean allowNonceIncrement,
            boolean isLocalCall,
            DataWord blockDifficulty,
            long blockNumber,
            long blockTimestamp,
            long blockNrgLimit,
            AionAddress blockCoinbase) {
        this(
                repositoryCache,
                allowNonceIncrement,
                isLocalCall,
                false,
                blockDifficulty,
                blockNumber,
                blockTimestamp,
                blockNrgLimit,
                blockCoinbase);
    }

    private DataWord blockDifficulty;
    private long blockNumber;
    private long blockTimestamp;
    private long blockNrgLimit;
    private AionAddress blockCoinbase;

    public KernelInterfaceForFastVM(
            RepositoryCache<AccountState, IBlockStoreBase<?, ?>> repositoryCache,
            boolean allowNonceIncrement,
            boolean isLocalCall,
            boolean fork040Enable,
            DataWord blockDifficulty,
            long blockNumber,
            long blockTimestamp,
            long blockNrgLimit,
            AionAddress blockCoinbase) {

        if (repositoryCache == null) {
            throw new NullPointerException("Cannot set null repositoryCache!");
        }
        this.repositoryCache = repositoryCache;
        this.allowNonceIncrement = allowNonceIncrement;
        this.isLocalCall = isLocalCall;
        this.fork040Enable = fork040Enable;
        this.blockDifficulty = blockDifficulty;
        this.blockNumber = blockNumber;
        this.blockTimestamp = blockTimestamp;
        this.blockNrgLimit = blockNrgLimit;
        this.blockCoinbase = blockCoinbase;
    }

    @Override
    public KernelInterfaceForFastVM makeChildKernelInterface() {
        return new KernelInterfaceForFastVM(
                this.repositoryCache.startTracking(),
                this.allowNonceIncrement,
                this.isLocalCall,
                this.fork040Enable,
                this.blockDifficulty,
                this.blockNumber,
                this.blockTimestamp,
                this.blockNrgLimit,
                this.blockCoinbase);
    }

    @Override
    public void commit() {
        this.repositoryCache.flush();
    }

    @Override
    public void commitTo(KernelInterface target) {
        this.repositoryCache.flushTo(((KernelInterfaceForFastVM) target).repositoryCache, false);
    }

    // The below 2 methods will be removed during the next phase of refactoring. They are temporary.
    public void rollback() {
        this.repositoryCache.rollback();
    }

    public RepositoryCache<AccountState, IBlockStoreBase<?, ?>> getRepositoryCache() {
        return this.repositoryCache;
    }

    @Override
    public void createAccount(AionAddress address) {
        this.repositoryCache.createAccount(address);
    }

    public void setVmType(AionAddress address) {
        this.repositoryCache.saveVmType(address, InternalVmType.FVM);
    }

    @Override
    public boolean hasAccountState(AionAddress address) {
        return this.repositoryCache.hasAccountState(address);
    }

    @Override
    public void putCode(AionAddress address, byte[] code) {
        // ensure the vm type is set as soon as the account becomes a contract
        this.repositoryCache.saveCode(address, code);
        setVmType(address);
    }

    @Override
    public byte[] getCode(AionAddress address) {
        return this.repositoryCache.getCode(address);
    }

    @Override
    public byte[] getTransformedCode(AionAddress address) {
        // Todo:implement it for fvm later.
        throw new UnsupportedOperationException();
    }

    @Override
    public void setTransformedCode(AionAddress address, byte[] code) {
        // Todo:implement it for fvm later.
        throw new UnsupportedOperationException();
    }

    @Override
    public void putObjectGraph(AionAddress contract, byte[] graph) {
        throw new UnsupportedOperationException("The FVM does not use an object graph.");
    }

    @Override
    public byte[] getObjectGraph(AionAddress contract) {
        throw new UnsupportedOperationException("The FVM does not use an object graph.");
    }

    @Override
    public void putStorage(AionAddress address, byte[] key, byte[] value) {
        ByteArrayWrapper storageKey = alignDataToWordSize(key);
        ByteArrayWrapper storageValue = alignValueToWordSizeForPut(value);
        if (value == null || value.length == 0 || storageValue.isZero()) {
            // used to ensure FVM correctness
            throw new IllegalArgumentException(
                    "Put with null, empty or zero byte array values is not allowed for the FVM. For deletions, make explicit calls to the delete method.");
        }

        this.repositoryCache.addStorageRow(address, storageKey, storageValue);
        setVmType(address);
    }

    @Override
    public void removeStorage(AionAddress address, byte[] key) {
        ByteArrayWrapper storageKey = alignDataToWordSize(key);
        this.repositoryCache.removeStorageRow(address, storageKey);
        setVmType(address);
    }

    @Override
    public byte[] getStorage(AionAddress address, byte[] key) {
        ByteArrayWrapper storageKey = alignDataToWordSize(key);
        ByteArrayWrapper value = this.repositoryCache.getStorageValue(address, storageKey);
        if (value != null && (value.isZero() || value.isEmpty())) {
            // used to ensure FVM correctness
            throw new IllegalStateException(
                    "A zero or empty value was retrieved from storage. Storing zeros is not allowed by the FVM. An incorrect put was previously performed instead of an explicit call to the delete method.");
        }
        return (value == null) ? DataWordImpl.ZERO.getData() : alignValueToWordSizeForGet(value);
    }

    @Override
    public void deleteAccount(AionAddress address) {
        if (!this.isLocalCall) {
            this.repositoryCache.deleteAccount(address);
        }
    }

    @Override
    public BigInteger getBalance(AionAddress address) {
        return this.repositoryCache.getBalance(address);
    }

    @Override
    public void adjustBalance(AionAddress address, BigInteger delta) {
        this.repositoryCache.addBalance(address, delta);
    }

    @Override
    public byte[] getBlockHashByNumber(long blockNumber) {
        return this.repositoryCache.getBlockStore().getBlockHashByNumber(blockNumber);
    }

    @Override
    public BigInteger getNonce(AionAddress address) {
        return this.repositoryCache.getNonce(address);
    }

    @Override
    public void incrementNonce(AionAddress address) {
        if (!this.isLocalCall && this.allowNonceIncrement) {
            this.repositoryCache.incrementNonce(address);
        }
    }

    @Override
    public void deductEnergyCost(AionAddress address, BigInteger energyCost) {
        if (!this.isLocalCall) {
            this.repositoryCache.addBalance(address, energyCost.negate());
        }
    }

    @Override
    public void refundAccount(AionAddress address, BigInteger amount) {
        if (!this.isLocalCall) {
            this.repositoryCache.addBalance(address, amount);
        }
    }

    @Override
    public void payMiningFee(AionAddress miner, BigInteger fee) {
        if (!this.isLocalCall) {
            this.repositoryCache.addBalance(miner, fee);
        }
    }

    @Override
    public boolean accountNonceEquals(AionAddress address, BigInteger nonce) {
        return (this.isLocalCall) ? true : getNonce(address).equals(nonce);
    }

    @Override
    public boolean accountBalanceIsAtLeast(AionAddress address, BigInteger amount) {
        return (this.isLocalCall) ? true : getBalance(address).compareTo(amount) >= 0;
    }

    @Override
    public boolean isValidEnergyLimitForCreate(long energyLimit) {
        return (this.isLocalCall) ? true : TxNrgRule.isValidNrgContractCreate(energyLimit);
    }

    @Override
    public boolean isValidEnergyLimitForNonCreate(long energyLimit) {
        return (this.isLocalCall) ? true : TxNrgRule.isValidNrgTx(energyLimit);
    }

    @Override
    public boolean destinationAddressIsSafeForThisVM(AionAddress address) {
        return getVmType(address) != InternalVmType.AVM;
    }

    private InternalVmType getVmType(AionAddress destination) {
        InternalVmType storedVmType = repositoryCache.getVMUsed(destination);

        // DEFAULT is returned when there was no contract information stored
        if (storedVmType == InternalVmType.UNKNOWN) {
            // will load contract into memory otherwise leading to consensus issues
            RepositoryCache track = repositoryCache.startTracking();
            return track.getVmType(destination);
        } else {
            return storedVmType;
        }
    }

    /**
     * If data.length > 16 then data is aligned to be 32 bytes.
     *
     * <p>Otherwise it is aligned to be 16 bytes with all of its leading zero bytes removed.
     *
     * <p>This method should only be used for putting data into storage.
     */
    private ByteArrayWrapper alignValueToWordSizeForPut(byte[] value) {
        if (value.length == DoubleDataWord.BYTES) {
            return new ByteArrayWrapper(new DoubleDataWord(value).getData());
        } else {
            DataWordImpl valueAsWord = new DataWordImpl(value);
            return (valueAsWord.isZero())
                    ? valueAsWord.toWrapper()
                    : new ByteArrayWrapper(valueAsWord.getNoLeadZeroesData());
        }
    }

    /**
     * If data.length > 16 then data is aligned to be 32 bytes.
     *
     * <p>Otherwise it is aligned to be 16 bytes.
     *
     * <p>This method should only be used for getting data from storage.
     */
    private byte[] alignValueToWordSizeForGet(ByteArrayWrapper wrappedValue) {
        byte[] value = wrappedValue.getData();

        if (value.length > DataWordImpl.BYTES) {
            return new DoubleDataWord(value).getData();
        } else {
            return new DataWordImpl(value).getData();
        }
    }

    /**
     * If data.length > 16 then data is aligned to be 32 bytes.
     *
     * <p>Otherwise it is aligned to be 16 bytes.
     *
     * <p>Takes a byte[] and outputs a {@link ByteArrayWrapper}.
     */
    private ByteArrayWrapper alignDataToWordSize(byte[] data) {
        if (data.length == DoubleDataWord.BYTES) {
            return new ByteArrayWrapper(new DoubleDataWord(data).getData());
        } else {
            return new ByteArrayWrapper(new DataWordImpl(data).getData());
        }
    }

    public boolean isFork040Enable() {
        return this.fork040Enable;
    }

    @Override
    public long getBlockNumber() {
        return blockNumber;
    }

    @Override
    public long getBlockTimestamp() {
        return blockTimestamp;
    }

    @Override
    public long getBlockEnergyLimit() {
        return blockNrgLimit;
    }

    @Override
    public long getBlockDifficulty() {
        if (blockDifficulty instanceof DataWordImpl) {
            return ((DataWordImpl) blockDifficulty).longValue();
        } else {
            return ((DoubleDataWord) blockDifficulty).longValue();
        }
    }

    @Override
    public AionAddress getMinerAddress() {
        return blockCoinbase;
    }
}
