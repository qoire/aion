package org.aion.zero.impl.db;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.aion.mcf.db.ContractDetails;
import org.aion.mcf.vm.DataWord;
import org.aion.mcf.vm.types.DataWordImpl;
import org.aion.mcf.vm.types.DoubleDataWord;
import org.aion.util.conversions.Hex;
import org.aion.util.types.ByteArrayWrapper;
import org.apache.commons.lang3.RandomUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class IContractDetailsTest {
    // The two ways of instantiating the cache.
    private ContractDetails cache1, cache2;

    @Before
    public void setup() {
        cache1 = new AionContractDetailsImpl();
        cache2 = new ContractDetailsCacheImpl(new AionContractDetailsImpl());
    }

    @After
    public void tearDown() {
        cache1 = null;
        cache2 = null;
    }

    @Test
    public void testGetNoSuchSingleKey() {
        doGetNoSuchSingleKeyTest(cache1);
        doGetNoSuchSingleKeyTest(cache2);
    }

    @Test
    public void testGetNoSuchDoubleKey() {
        doGetNoSuchDoubleKeyTest(cache1);
        doGetNoSuchDoubleKeyTest(cache2);
    }

    @Test
    public void testPutSingleZeroValue() {
        ByteArrayWrapper key =
                new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        checkGetNonExistentPairing(cache1, key);
        checkGetNonExistentPairing(cache2, key);

        key = new DoubleDataWord(RandomUtils.nextBytes(DoubleDataWord.BYTES)).toWrapper();
        checkGetNonExistentPairing(cache1, key);
        checkGetNonExistentPairing(cache2, key);
    }

    @Test
    public void testPutDoubleZeroValue() {
        ByteArrayWrapper key =
                new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        checkGetNonExistentPairing(cache1, key);
        checkGetNonExistentPairing(cache2, key);

        key = new DoubleDataWord(RandomUtils.nextBytes(DoubleDataWord.BYTES)).toWrapper();
        checkGetNonExistentPairing(cache1, key);
        checkGetNonExistentPairing(cache2, key);
    }

    @Test
    public void testPutSingleZeroKey() {
        ByteArrayWrapper value =
                new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        doPutSingleZeroKeyTest(cache1, value);
        doPutSingleZeroKeyTest(cache2, value);

        value = new DoubleDataWord(RandomUtils.nextBytes(DoubleDataWord.BYTES)).toWrapper();
        doPutSingleZeroKeyTest(cache1, value);
        doPutSingleZeroKeyTest(cache2, value);
    }

    @Test
    public void testPutDoubleZeroKey() {
        ByteArrayWrapper value =
                new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        doPutDoubleZeroKeyTest(cache1, value);
        doPutDoubleZeroKeyTest(cache2, value);

        value = new DoubleDataWord(RandomUtils.nextBytes(DoubleDataWord.BYTES)).toWrapper();
        doPutDoubleZeroKeyTest(cache1, value);
        doPutDoubleZeroKeyTest(cache2, value);
    }

    @Test
    public void testPutZeroKeyAndValue() {
        // Try single-single
        cache1.delete(DataWordImpl.ZERO.toWrapper());
        ByteArrayWrapper result = cache1.get(DataWordImpl.ZERO.toWrapper());
        assertNull(result);
        cache2.delete(DataWordImpl.ZERO.toWrapper());
        assertNull(cache2.get(DataWordImpl.ZERO.toWrapper()));

        // Try single-double
        cache1.delete(DataWordImpl.ZERO.toWrapper());
        result = cache1.get(DataWordImpl.ZERO.toWrapper());
        assertNull(result);
        cache2.delete(DataWordImpl.ZERO.toWrapper());
        assertNull(cache2.get(DataWordImpl.ZERO.toWrapper()));

        // Try double-single
        cache1.delete(DoubleDataWord.ZERO.toWrapper());
        result = cache1.get(DoubleDataWord.ZERO.toWrapper());
        assertNull(result);
        cache2.delete(DoubleDataWord.ZERO.toWrapper());
        assertNull(cache2.get(DoubleDataWord.ZERO.toWrapper()));

        // Try double-double
        cache1.delete(DoubleDataWord.ZERO.toWrapper());
        result = cache1.get(DoubleDataWord.ZERO.toWrapper());
        assertNull(result);
        cache2.delete(DoubleDataWord.ZERO.toWrapper());
        assertNull(cache2.get(DoubleDataWord.ZERO.toWrapper()));
    }

    @Test
    public void testPutKeyValueThenOverwriteValueWithZero() {
        // single-single
        ByteArrayWrapper key =
                new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        ByteArrayWrapper value =
                new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        doPutKeyValueThenOverwriteValueWithZero(cache1, key, value);
        doPutKeyValueThenOverwriteValueWithZero(cache2, key, value);

        // single-double
        value = new DoubleDataWord(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        doPutKeyValueThenOverwriteValueWithZero(cache1, key, value);
        doPutKeyValueThenOverwriteValueWithZero(cache2, key, value);

        // double-single
        key = new DoubleDataWord(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        value = new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        doPutKeyValueThenOverwriteValueWithZero(cache1, key, value);
        doPutKeyValueThenOverwriteValueWithZero(cache2, key, value);

        // double-double
        key = new DoubleDataWord(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        value = new DoubleDataWord(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        doPutKeyValueThenOverwriteValueWithZero(cache1, key, value);
        doPutKeyValueThenOverwriteValueWithZero(cache2, key, value);
    }

    @Test
    public void testPutAndGetEnMass() {
        int numEntries = RandomUtils.nextInt(1_000, 5_000);
        int deleteOdds = 4;
        List<ByteArrayWrapper> keys = getKeysInBulk(numEntries);
        List<ByteArrayWrapper> values = getValuesInBulk(numEntries);
        massPutIntoCache(cache1, keys, values);
        deleteEveryNthEntry(cache1, keys, deleteOdds);
        checkAllPairs(cache1, keys, values, deleteOdds);

        massPutIntoCache(cache2, keys, values);
        deleteEveryNthEntry(cache2, keys, deleteOdds);
        checkAllPairs(cache2, keys, values, deleteOdds);
    }

    @Test
    public void testGetStorage() {
        int numEntries = RandomUtils.nextInt(1_000, 5_000);
        int deleteOdds = 6;
        List<ByteArrayWrapper> keys = getKeysInBulk(numEntries);
        List<ByteArrayWrapper> values = getValuesInBulk(numEntries);
        massPutIntoCache(cache1, keys, values);
        deleteEveryNthEntry(cache1, keys, deleteOdds);
        checkStorage(cache1, keys, values, deleteOdds);

        massPutIntoCache(cache2, keys, values);
        deleteEveryNthEntry(cache2, keys, deleteOdds);
        checkStorage(cache2, keys, values, deleteOdds);
    }

    @Test
    public void testSetZeroValueViaSetStorage() {
        doSetZeroValueViaStorageTest(cache1);
        doSetZeroValueViaStorageTest(cache2);
    }

    @Test
    public void testSetStorageEnMass() {
        int numEntries = RandomUtils.nextInt(1_000, 5_000);
        int deleteOdds = 7;
        Map<ByteArrayWrapper, ByteArrayWrapper> storage =
                getKeyValueMappingInBulk(numEntries, deleteOdds);
        cache1.setStorage(storage);
        checkKeyValueMapping(cache1, storage);

        cache2.setStorage(storage);
        checkKeyValueMapping(cache2, storage);
    }

    /**
     * This test is specific to the ContractDetailsCacheImpl class, which has a commit method. This
     * test class is not concerned with testing all of the functionality of this method, only with
     * how this method handles zero-byte values.
     */
    @Test
    public void testCommitEnMassOriginalIsAionContract() {
        ContractDetailsCacheImpl impl = new ContractDetailsCacheImpl(cache1);

        int numEntries = RandomUtils.nextInt(1_000, 5_000);
        int deleteOdds = 3;
        List<ByteArrayWrapper> keys = getKeysInBulk(numEntries);
        List<ByteArrayWrapper> values = getValuesInBulk(numEntries);
        massPutIntoCache(impl, keys, values);
        deleteEveryNthEntry(impl, keys, deleteOdds);

        Map<ByteArrayWrapper, ByteArrayWrapper> storage = impl.getStorage(keys);
        assertEquals(0, cache1.getStorage(keys).size());
        impl.commit();
        assertEquals(storage.size(), cache1.getStorage(keys).size());

        int count = 1;
        for (ByteArrayWrapper key : keys) {
            try {
                if (count % deleteOdds == 0) {
                    assertNull(impl.get(key));
                    assertNull(cache1.get(key));
                } else {
                    assertEquals(impl.get(key), cache1.get(key));
                }
            } catch (AssertionError e) {
                System.err.println("\nAssertion failed on key: " + Hex.toHexString(key.getData()));
                e.printStackTrace();
            }
            count++;
        }
    }

    /**
     * This test is specific to the ContractDetailsCacheImpl class, which has a commit method. This
     * test class is not concerned with testing all of the functionality of this method, only with
     * how this method handles zero-byte values.
     */
    @Test
    public void testCommitEnMassOriginalIsContractDetails() {
        ContractDetailsCacheImpl impl = new ContractDetailsCacheImpl(cache2);

        int numEntries = RandomUtils.nextInt(1_000, 5_000);
        int deleteOdds = 3;
        List<ByteArrayWrapper> keys = getKeysInBulk(numEntries);
        List<ByteArrayWrapper> values = getValuesInBulk(numEntries);
        massPutIntoCache(impl, keys, values);
        deleteEveryNthEntry(impl, keys, deleteOdds);

        Map<ByteArrayWrapper, ByteArrayWrapper> storage = impl.getStorage(keys);
        assertEquals(0, cache2.getStorage(keys).size());
        impl.commit();
        assertEquals(storage.size(), cache2.getStorage(keys).size());

        int count = 1;
        for (ByteArrayWrapper key : keys) {
            try {
                if (count % deleteOdds == 0) {
                    assertNull(impl.get(key));
                    assertNull(cache2.get(key));
                } else {
                    assertEquals(impl.get(key), cache2.get(key));
                }
            } catch (AssertionError e) {
                System.err.println("\nAssertion failed on key: " + Hex.toHexString(key.getData()));
                e.printStackTrace();
            }
            count++;
        }
    }

    /**
     * This test is specific to the ContractDetailsCacheImpl class, which at times holds a different
     * storage value for contracts. This test checks that after an update to the cache object, the
     * original value from the contract details is not returned for use.
     */
    @Test
    public void testCacheUpdatedAndGetWithOriginalAionContract() {

        ByteArrayWrapper key = getRandomWord(true).toWrapper();
        ByteArrayWrapper value1 = getRandomWord(true).toWrapper();
        ByteArrayWrapper value2 = getRandomWord(true).toWrapper();

        // ensure the second value is different
        // unlikely to be necessary
        while (Arrays.equals(value1.getData(), value2.getData())) {
            value2 = getRandomWord(true).toWrapper();
        }

        // ensure the initial cache has the value
        cache1.put(key, value1);

        ContractDetailsCacheImpl impl = new ContractDetailsCacheImpl(cache1);

        // check that original value is retrieved
        assertThat(impl.get(key)).isEqualTo(value1);

        // delete and check that value is missing
        impl.delete(key);
        assertThat(impl.get(key)).isEqualTo(null);

        // add new value and check correctness
        impl.put(key, value2);
        assertThat(impl.get(key)).isEqualTo(value2);

        // clean-up
        cache1.delete(key);
    }

    // <------------------------------------------HELPERS------------------------------------------->

    /**
     * Tests calling get() on a DataWordImpl key that is not in cache -- first on a zero-byte key
     * and then on a random key.
     */
    private void doGetNoSuchSingleKeyTest(ContractDetails cache) {
        checkGetNonExistentPairing(cache, DataWordImpl.ZERO.toWrapper());
        checkGetNonExistentPairing(
                cache, new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper());
    }

    /**
     * Tests calling get() on a DoubleDataWord key that is not in cache -- first on a zero-byte key
     * and then on a random key.
     */
    private void doGetNoSuchDoubleKeyTest(ContractDetails cache) {
        checkGetNonExistentPairing(cache, DoubleDataWord.ZERO.toWrapper());
        checkGetNonExistentPairing(
                cache, new DoubleDataWord(RandomUtils.nextBytes(DoubleDataWord.BYTES)).toWrapper());
    }

    /** Tests putting value into cache with a zero-byte DataWordImpl key. */
    private void doPutSingleZeroKeyTest(ContractDetails cache, ByteArrayWrapper value) {
        cache.put(DataWordImpl.ZERO.toWrapper(), value);
        assertEquals(value, cache.get(DataWordImpl.ZERO.toWrapper()));
    }

    /** Tests putting value into cache with a zero-byte DoubleDataWord key. */
    private void doPutDoubleZeroKeyTest(ContractDetails cache, ByteArrayWrapper value) {
        cache.put(DoubleDataWord.ZERO.toWrapper(), value);
        assertEquals(value, cache.get(DoubleDataWord.ZERO.toWrapper()));
    }

    /**
     * Tests putting key and value into cache and then putting a zero-byte data word into cache with
     * key and then calling get() on that key.
     */
    private void doPutKeyValueThenOverwriteValueWithZero(
            ContractDetails cache, ByteArrayWrapper key, ByteArrayWrapper value) {

        // Test DataWordImpl.
        cache.put(key, value);
        assertEquals(value, cache.get(key));
        cache.delete(key);
        checkGetNonExistentPairing(cache, key);

        // Test DoubleDataWord.
        cache.put(key, value);
        assertEquals(value, cache.get(key));
        cache.delete(key);
        checkGetNonExistentPairing(cache, key);
    }

    /**
     * Checks that cache contains all key-value pairs in keys and values, where it is assumed every
     * n'th pair was deleted.
     */
    private void checkAllPairs(
            ContractDetails cache,
            List<ByteArrayWrapper> keys,
            List<ByteArrayWrapper> values,
            int n) {

        int size = keys.size();
        assertEquals(size, values.size());
        int count = 1;
        for (ByteArrayWrapper key : keys) {
            if (count % n == 0) {
                checkGetNonExistentPairing(cache, key);
            } else {
                assertEquals(values.get(count - 1), cache.get(key));
            }
            count++;
        }
    }

    /**
     * Checks that cache's storage, given by cache.getStorage(), contains all key-value pairs in
     * keys and values, where it is assumed every n'th pair was deleted.
     */
    private void checkStorage(
            ContractDetails cache,
            List<ByteArrayWrapper> keys,
            List<ByteArrayWrapper> values,
            int n) {

        Map<ByteArrayWrapper, ByteArrayWrapper> storage = cache.getStorage(keys);
        int count = 1;
        for (ByteArrayWrapper key : keys) {
            if (count % n == 0) {
                try {
                    assertNull(storage.get(key));
                } catch (AssertionError e) {
                    System.err.println(
                            "\nAssertion failed on key: " + Hex.toHexString(key.getData()));
                    e.printStackTrace();
                }
            } else {
                assertEquals(values.get(count - 1), storage.get(key));
            }
            count++;
        }
    }

    /**
     * Iterates over every key in keys -- which are assumed to exist in cache -- and then deletes
     * any key-value pair in cache for every n'th key in keys.
     */
    private void deleteEveryNthEntry(ContractDetails cache, List<ByteArrayWrapper> keys, int n) {
        int count = 1;
        for (ByteArrayWrapper key : keys) {
            if (count % n == 0) {
                cache.delete(key);
            }
            count++;
        }
    }

    /** Puts all of the key-value pairs in keys and values into cache. */
    private void massPutIntoCache(
            ContractDetails cache, List<ByteArrayWrapper> keys, List<ByteArrayWrapper> values) {

        int size = keys.size();
        assertEquals(size, values.size());
        for (int i = 0; i < size; i++) {
            ByteArrayWrapper value = values.get(i);
            if (value == null || value.isZero()) {
                cache.delete(keys.get(i));
            } else {
                cache.put(keys.get(i), values.get(i));
            }
        }
    }

    /** Returns a list of numKeys keys, every other one is single and then double. */
    private List<ByteArrayWrapper> getKeysInBulk(int numKeys) {
        List<ByteArrayWrapper> keys = new ArrayList<>(numKeys);
        boolean isSingleKey = true;
        for (int i = 0; i < numKeys; i++) {
            keys.add(getRandomWord(isSingleKey).toWrapper());
            isSingleKey = !isSingleKey;
        }
        return keys;
    }

    /** Returns a list of numValues values, every other one is single and then double. */
    private List<ByteArrayWrapper> getValuesInBulk(int numValues) {
        List<ByteArrayWrapper> values = new ArrayList<>(numValues);
        boolean isSingleValue = true;
        for (int i = 0; i < numValues; i++) {
            values.add(getRandomWord(isSingleValue).toWrapper());
            isSingleValue = !isSingleValue;
        }
        return values;
    }

    /** Returns a random DataWordImpl if isSingleWord is true, otherwise a random DoubleDataWord. */
    private DataWord getRandomWord(boolean isSingleWord) {
        return (isSingleWord)
                ? new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES))
                : new DoubleDataWord(RandomUtils.nextBytes(DoubleDataWord.BYTES));
    }

    /**
     * Sets a key-value pair with a zero value via cache.setStorage() and ensures that null is
     * returned when called on that same key.
     */
    private void doSetZeroValueViaStorageTest(ContractDetails cache) {
        Map<ByteArrayWrapper, ByteArrayWrapper> storage = new HashMap<>();
        ByteArrayWrapper key =
                new DataWordImpl(RandomUtils.nextBytes(DataWordImpl.BYTES)).toWrapper();
        storage.put(key, null);
        cache.setStorage(storage);
        checkGetNonExistentPairing(cache, key);
    }

    /** Checks cache returns the expected values given its storage is storage. */
    private void checkKeyValueMapping(
            ContractDetails cache, Map<ByteArrayWrapper, ByteArrayWrapper> storage) {

        for (ByteArrayWrapper key : storage.keySet()) {
            ByteArrayWrapper value = storage.get(key);
            if (value == null) {
                checkGetNonExistentPairing(cache, key);
            } else {
                assertEquals(value, cache.get(key));
            }
        }
    }

    /**
     * Returns a key-value mapping with numEntries mappings, where every n'th mapping has a zero
     * value.
     */
    private Map<ByteArrayWrapper, ByteArrayWrapper> getKeyValueMappingInBulk(
            int numEntries, int n) {
        Map<ByteArrayWrapper, ByteArrayWrapper> storage = new HashMap<>(numEntries);
        List<ByteArrayWrapper> keys = getKeysInBulk(numEntries);
        List<ByteArrayWrapper> values = getValuesInBulk(numEntries);
        int size = keys.size();
        assertEquals(size, values.size());
        for (int i = 0; i < size; i++) {
            if ((i + 1) % n == 0) {
                storage.put(keys.get(i), null);
            } else {
                storage.put(keys.get(i), values.get(i));
            }
        }
        return storage;
    }

    /**
     * Assumption: key has no valid value mapping in cache. This method calls cache.get(key) and
     * checks its result.
     */
    private void checkGetNonExistentPairing(ContractDetails cache, ByteArrayWrapper key) {
        try {
            assertNull(cache.get(key));
        } catch (AssertionError e) {
            System.err.println("\nAssertion failed on key: " + Hex.toHexString(key.getData()));
            e.printStackTrace();
        }
    }
}
