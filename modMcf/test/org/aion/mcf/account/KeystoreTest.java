package org.aion.mcf.account;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.aion.crypto.ECKey;
import org.aion.crypto.ECKeyFac;
import org.aion.types.AionAddress;
import org.aion.util.bytes.ByteUtil;
import org.aion.util.types.AddressUtils;
import org.aion.util.types.ByteArrayWrapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class KeystoreTest {
    private List<String> filesToRemove = new ArrayList<>();

    private static String randomPassword() {
        Random rand = new Random();
        StringBuilder sb = new StringBuilder(10);
        while (sb.length() < 10) {
            char c = (char) (rand.nextInt() & Character.MAX_VALUE);
            if (Character.isDefined(c)) sb.append(c);
        }
        return sb.toString();
    }

    private static final String KEYSTORE_PATH;

    static {
        String storageDir = System.getProperty("local.storage.dir");
        if (storageDir == null || storageDir.equalsIgnoreCase("")) {
            storageDir = System.getProperty("user.dir");
        }
        KEYSTORE_PATH = storageDir + "/keystore";
    }

    @Before
    public void init() {
        ECKeyFac.setType(ECKeyFac.ECKeyType.ED25519);
    }

    @After
    public void clean() {
        if (filesToRemove.size() == 0) return;
        for (int i = 0; i < filesToRemove.size(); i++) {
            cleanFiles(filesToRemove.get(i));
            filesToRemove.remove(filesToRemove.get(i));
        }
        assertEquals(0, filesToRemove.size());
    }

    @Test
    public void keyCreateAndRetrieve() {
        String password = randomPassword();
        String address = Keystore.create(password);
        assertNotNull(address);
        assertEquals(address.length(), 2 + 64);
        System.out.println("new addr: " + address);
        ECKey key = Keystore.getKey(address, password);
        assertNotNull(key);
        filesToRemove.add(address);
    }

    @Test
    public void keyCreateAndRetrieve2() {
        String password = randomPassword();
        String address = Keystore.create(password);
        assertNotNull(address);
        assertEquals(address.length(), 2 + 64);
        System.out.println("new addr: " + address);
        ECKey key = Keystore.getKey(address, password);
        assertNotNull(key);
        assertEquals("0x", (Keystore.create(password, key)));
        filesToRemove.add(address);
    }

    @Test
    public void testKeyCreate() {
        String password = randomPassword();

        ECKey key = ECKeyFac.inst().create();
        assertNotNull(key);

        String addr = Keystore.create(password, key);
        assertEquals(addr.substring(2), ByteUtil.toHexString(key.getAddress()));
        filesToRemove.add(addr);
    }

    @Test
    public void testKeyExist() {
        String password = randomPassword();
        String address = Keystore.create(password);
        assertNotNull(address);
        assertEquals(address.length(), 2 + 64);
        System.out.println("new addr: " + address);
        ECKey key = Keystore.getKey(address, password);
        assertNotNull(key);
        assertTrue(Keystore.exist(address));
        filesToRemove.add(address);
    }

    @Test
    public void testWrongAddress() {
        String wAddr = "0xb000000000000000000000000000000000000000000000000000000000000000";
        assertFalse(Keystore.exist(wAddr));

        String wAddr1 = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assertFalse(Keystore.exist(wAddr1));
    }

    @Test
    public void testAccountExport() {
        String password = randomPassword();
        ECKey key = ECKeyFac.inst().create();
        assertNotNull(key);

        String addr = Keystore.create(password, key);
        assertEquals(addr.substring(2), ByteUtil.toHexString(key.getAddress()));

        Map<AionAddress, String> arg = new HashMap<>();
        arg.put(AddressUtils.wrapAddress(addr), password);

        Map<AionAddress, ByteArrayWrapper> export = Keystore.exportAccount(arg);

        assertTrue(export.containsKey(AddressUtils.wrapAddress(addr)));
        assertTrue(export.containsValue(ByteArrayWrapper.wrap(key.getPrivKeyBytes())));
        filesToRemove.add(addr);
    }

    @Test
    public void testAccountBackup() {
        String password = randomPassword();
        ECKey key = ECKeyFac.inst().create();
        assertNotNull(key);

        String addr = Keystore.create(password, key);
        assertEquals(addr.substring(2), ByteUtil.toHexString(key.getAddress()));

        Map<AionAddress, String> arg = new HashMap<>();
        arg.put(AddressUtils.wrapAddress(addr), password);

        Map<AionAddress, ByteArrayWrapper> export = Keystore.backupAccount(arg);

        assertNotNull(export);

        File f = Keystore.getAccountFile(addr.substring(2), password);
        assertNotNull(f);

        assertTrue(export.containsKey(AddressUtils.wrapAddress(addr)));
        try {
            assertTrue(export.containsValue(ByteArrayWrapper.wrap(Files.readAllBytes(f.toPath()))));
        } catch (IOException e) {
            e.printStackTrace();
        }
        filesToRemove.add(addr);
    }

    @Test
    public void testList() {
        String password = randomPassword();
        ECKey key = ECKeyFac.inst().create();
        assertNotNull(key);

        String addr = Keystore.create(password, key);
        assertEquals(addr.substring(2), ByteUtil.toHexString(key.getAddress()));

        String[] addrList = Keystore.list();

        assertNotNull(addrList);

        boolean hasAddr = false;
        for (String s : addrList) {
            if (s.equals(addr)) {
                hasAddr = true;
                break;
            }
        }

        assertTrue(hasAddr);
        filesToRemove.add(addr);
    }

    @Test(expected = NullPointerException.class)
    public void testBackupAccountWithNullInput() {
        Keystore.backupAccount(null);
    }

    @Test(expected = NullPointerException.class)
    public void testImportAccountNull() {
        Keystore.importAccount(null);
    }

    private static void cleanFiles(String address) {
        // get a list of all the files in keystore directory
        File folder = new File(KEYSTORE_PATH);
        File[] AllFilesInDirectory = folder.listFiles();

        // check for invalid or wrong path - should not happen
        if (AllFilesInDirectory == null) return;

        for (File file : AllFilesInDirectory) {
            String ending = "";
            if (file.getName().length() > 64) {
                ending = file.getName().substring(file.getName().length() - 64);
            }

            if (ending.equals(address.substring(2))) {
                File f = new File(KEYSTORE_PATH + "/" + file.getName());
                f.delete();
            }
        }
    }
}
