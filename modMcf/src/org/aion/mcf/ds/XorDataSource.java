package org.aion.mcf.ds;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.aion.interfaces.db.ByteArrayKeyValueStore;
import org.aion.util.bytes.ByteUtil;

public class XorDataSource implements ByteArrayKeyValueStore {
    private final ByteArrayKeyValueStore source;
    private final byte[] subKey;

    public XorDataSource(ByteArrayKeyValueStore source, byte[] subKey) {
        this.source = source;
        this.subKey = subKey;
    }

    private byte[] convertKey(byte[] key) {
        return ByteUtil.xorAlignRight(key, subKey);
    }

    @Override
    public Optional<byte[]> get(byte[] key) {
        return source.get(convertKey(key));
    }

    @Override
    public void put(byte[] key, byte[] value) {
        source.put(convertKey(key), value);
    }

    @Override
    public void delete(byte[] key) {
        source.delete(convertKey(key));
    }

    @Override
    public Iterator<byte[]> keys() {
        return new XorDSIteratorWrapper(source.keys());
    }

    /**
     * A wrapper for the iterator needed by {@link XorDataSource} conforming to the {@link Iterator}
     * interface.
     *
     * @author Alexandra Roatis
     */
    private class XorDSIteratorWrapper implements Iterator<byte[]> {
        final Iterator<byte[]> sourceIterator;

        /**
         * @implNote Building two wrappers for the same {@link Iterator} will lead to inconsistent
         *     behavior.
         */
        XorDSIteratorWrapper(final Iterator<byte[]> sourceIterator) {
            this.sourceIterator = sourceIterator;
        }

        @Override
        public boolean hasNext() {
            return sourceIterator.hasNext();
        }

        @Override
        public byte[] next() {
            return convertKey(sourceIterator.next());
        }
    }

    @Override
    public void putBatch(Map<byte[], byte[]> rows) {
        Map<byte[], byte[]> converted = new HashMap<>(rows.size());
        for (Map.Entry<byte[], byte[]> entry : rows.entrySet()) {
            converted.put(convertKey(entry.getKey()), entry.getValue());
        }
        source.putBatch(converted);
    }

    @Override
    public void close() throws Exception {
        source.close();
    }

    @Override
    public void deleteBatch(Collection<byte[]> keys) {
        List<byte[]> converted = new ArrayList<>(keys.size());
        for (byte[] key : keys) {
            converted.add(convertKey(key));
        }
        source.deleteBatch(converted);
    }

    @Override
    public void check() {
        source.check();
    }

    @Override
    public boolean isEmpty() {
        return source.isEmpty();
    }

    @Override
    public void putToBatch(byte[] key, byte[] value) {
        source.putToBatch(convertKey(key), value);
    }

    @Override
    public void deleteInBatch(byte[] key) {
        source.deleteInBatch(convertKey(key));
    }

    @Override
    public void commitBatch() {
        source.commitBatch();
    }
}
