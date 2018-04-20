package org.aion.db.generic;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import org.aion.base.db.IByteArrayKeyValueDatabase;
import org.aion.base.db.PersistenceMethod;
import org.aion.base.util.ByteArrayWrapper;
import org.aion.log.AionLoggerFactory;
import org.aion.log.LogEnum;
import org.slf4j.Logger;

/**
 * LRU map used for speeding up reads.
 *
 * @author Alexandra Roatis
 */
public class LRUCachedReadsDatabase implements IByteArrayKeyValueDatabase {

    private static final Logger LOG = AionLoggerFactory.getLogger(LogEnum.DB.name());

    /** Underlying database implementation. */
    protected IByteArrayKeyValueDatabase database;

    /** Keeps track of the entries that have been modified. */
    private LoadingCache<ByteArrayWrapper, Optional<byte[]>> loadingCache = null;

    /** The underlying cache maximum size. */
    private int maxSize;

    /** The flag to indicate if the stats are enabled or not. */
    private boolean statsEnabled;

    public LRUCachedReadsDatabase(
            IByteArrayKeyValueDatabase _database, int _maxSize, boolean _statsEnabled) {
        database = _database;
        maxSize = _maxSize;
        statsEnabled = _statsEnabled;
    }

    /**
     * Assists in setting up the underlying cache for the current instance.
     *
     * @param size
     * @param enableStats
     */
    private void setupLoadingCache(final long size, final boolean enableStats) {
        // Use CacheBuilder to create the cache.
        CacheBuilder<Object, Object> builder = CacheBuilder.newBuilder();

        // Set the size.
        // Actually when size is 0, we make it unbounded
        if (size != 0) {
            builder.maximumSize(size);
        }

        // Enable stats if passed in.
        if (enableStats) {
            builder.recordStats();
        }

        // Utilize CacheBuilder and pass in the parameters to create the cache.
        this.loadingCache =
                builder.build(
                        new CacheLoader<ByteArrayWrapper, Optional<byte[]>>() {
                            @Override
                            public Optional<byte[]> load(ByteArrayWrapper keyToLoad) {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug(
                                            getName().get()
                                                    + " -> value from READ CACHE with size = "
                                                    + loadingCache.size());
                                }
                                // It is safe to say keyToLoad is not null or the data is null.
                                // Load from the data source.
                                return database.get(keyToLoad.getData());
                            }
                        });
    }

    /**
     * For testing the lock functionality of public methods. Used to ensure that locks are released
     * after normal or exceptional execution.
     *
     * @return {@code true} when the resource is locked, {@code false} otherwise
     */
    @Override
    public boolean isLocked() {
        return database.isLocked();
    }

    @Override
    public boolean open() {
        if (isOpen()) {
            return true;
        }

        boolean open = database.open();

        // setup cache only id database was opened successfully
        if (open) {
            setupLoadingCache(maxSize, statsEnabled);
        }

        return open;
    }

    @Override
    public void check() {
        if (!database.isOpen()) {
            throw new RuntimeException("Database is not opened: " + this);
        }
    }

    @Override
    public void close() {
        try {
            // close database
            database.close();
        } finally {
            // clear the cache
            loadingCache.invalidateAll();
        }
    }

    @Override
    public boolean commit() {
        loadingCache.invalidateAll();
        return database.commit();
    }

    @Override
    public void compact() {
        database.compact();
    }

    @Override
    public Optional<String> getName() {
        return database.getName();
    }

    @Override
    public Optional<String> getPath() {
        return database.getPath();
    }

    @Override
    public boolean isOpen() {
        return database.isOpen();
    }

    @Override
    public boolean isClosed() {
        return database.isClosed();
    }

    @Override
    public boolean isAutoCommitEnabled() {
        return database.isAutoCommitEnabled();
    }

    @Override
    public PersistenceMethod getPersistenceMethod() {
        return database.getPersistenceMethod();
    }

    @Override
    public boolean isCreatedOnDisk() {
        return database.isCreatedOnDisk();
    }

    @Override
    public long approximateSize() {
        return database.approximateSize();
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName()
                + "<"
                + maxSize
                + ">"
                + " over "
                + this.database.toString();
    }

    @Override
    public boolean isEmpty() {
        if (loadingCache.size() > 0) {
            return false;
        } else {
            return database.isEmpty();
        }
    }

    @Override
    public Iterator<byte[]> keys() {
        return database.keys();
    }

    @Override
    public Optional<byte[]> get(byte[] k) {
        Optional<byte[]> val;

        try {
            val = loadingCache.get(ByteArrayWrapper.wrap(k));
        } catch (ExecutionException e) {
            LOG.error(
                    this.toString() + " cannot load from cache. Loading directly from database.",
                    e);
            return database.get(k);
        }

        return val;
    }

    @Override
    public void put(byte[] k, byte[] v) {
        loadingCache.put(ByteArrayWrapper.wrap(k), Optional.of(v));
        database.put(k, v);
    }

    @Override
    public void delete(byte[] k) {
        loadingCache.invalidate(ByteArrayWrapper.wrap(k));
        database.delete(k);
    }

    @Override
    public void putBatch(Map<byte[], byte[]> inputMap) {
        if (statsEnabled && LOG.isDebugEnabled()) {
            LOG.debug(getName().get() + " > " + loadingCache.stats().toString());
        }
        loadingCache.invalidateAll();
        database.putBatch(inputMap);
    }

    @Override
    public void putToBatch(byte[] k, byte[] v) {
        database.putToBatch(k, v);
    }

    @Override
    public void commitBatch() {
        if (statsEnabled && LOG.isDebugEnabled()) {
            LOG.debug(getName().get() + " > " + loadingCache.stats().toString());
        }
        loadingCache.invalidateAll();
        database.commitBatch();
    }

    @Override
    public void deleteBatch(Collection<byte[]> keys) {
        if (statsEnabled && LOG.isDebugEnabled()) {
            LOG.debug(getName().get() + " > " + loadingCache.stats().toString());
        }
        loadingCache.invalidateAll();
        database.deleteBatch(keys);
    }

    @Override
    public void drop() {
        loadingCache.invalidateAll();
        database.drop();
    }
}
