package org.aion.db.generic;

import java.util.*;
import org.aion.base.db.IByteArrayKeyValueDatabase;
import org.aion.base.db.PersistenceMethod;
import org.aion.base.util.ByteArrayWrapper;
import org.aion.log.AionLoggerFactory;
import org.aion.log.LogEnum;
import org.slf4j.Logger;

/**
 * Used for block and index where entries are typically accessed in order.
 *
 * @author Alexandra Roatis
 */
public class LightCachedReadsDatabase implements IByteArrayKeyValueDatabase {

    private static final Logger LOG = AionLoggerFactory.getLogger(LogEnum.DB.name());

    /** Underlying database implementation. */
    protected IByteArrayKeyValueDatabase database;

    /** Keeps track of the entries that have been modified. */
    private LinkedHashMap<ByteArrayWrapper, Optional<byte[]>> knownEntries;

    /** The underlying cache maximum size. */
    private int maxSize;

    public LightCachedReadsDatabase(IByteArrayKeyValueDatabase _database, int _maxSize) {
        database = _database;
        knownEntries = new LinkedHashMap<>();
        maxSize = _maxSize;
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
        return database.open();
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
            knownEntries.clear();
        }
    }

    @Override
    public boolean commit() {
        knownEntries.clear();
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
        if (knownEntries.size() > 0) {
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
        ByteArrayWrapper key = ByteArrayWrapper.wrap(k);

        if (knownEntries.size() > 0 && knownEntries.containsKey(key)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        getName().get()
                                + " -> value from READ CACHE with size = "
                                + knownEntries.size());
            }
            return knownEntries.get(key);
        }

        if (knownEntries.size() > maxSize) {
            knownEntries.remove(knownEntries.keySet().iterator().next());
        }

        Optional<byte[]> value = database.get(k);
        knownEntries.put(key, value);

        return value;
    }

    @Override
    public void put(byte[] k, byte[] v) {
        ByteArrayWrapper key = ByteArrayWrapper.wrap(k);

        knownEntries.remove(key);

        if (knownEntries.size() > maxSize) {
            knownEntries.remove(knownEntries.keySet().iterator().next());
        }

        knownEntries.put(key, Optional.of(v));

        database.put(k, v);
    }

    @Override
    public void delete(byte[] k) {
        knownEntries.remove(ByteArrayWrapper.wrap(k));
        database.delete(k);
    }

    @Override
    public void putBatch(Map<byte[], byte[]> inputMap) {
        knownEntries.clear();
        database.putBatch(inputMap);
    }

    @Override
    public void putToBatch(byte[] k, byte[] v) {
        database.putToBatch(k, v);
    }

    @Override
    public void commitBatch() {
        knownEntries.clear();
        database.commitBatch();
    }

    @Override
    public void deleteBatch(Collection<byte[]> keys) {
        knownEntries.clear();
        database.deleteBatch(keys);
    }

    @Override
    public void drop() {
        knownEntries.clear();
        database.drop();
    }
}
