package org.aion.mcf.account;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.aion.crypto.ECKey;
import org.aion.crypto.ECKeyFac;
import org.aion.log.AionLoggerFactory;
import org.aion.log.LogEnum;
import org.aion.types.AionAddress;
import org.aion.util.bytes.ByteUtil;
import org.aion.util.conversions.Hex;
import org.aion.util.string.StringUtils;
import org.aion.util.types.AddressUtils;
import org.aion.util.types.ByteArrayWrapper;
import org.slf4j.Logger;

/** key store class. */
public class Keystore {

    private static final Logger LOG = AionLoggerFactory.getLogger(LogEnum.API.name());
    private static final FileDateTimeComparator COMPARE = new FileDateTimeComparator();
    private static final Pattern HEX_64 = Pattern.compile("^[\\p{XDigit}]{64}$");
    private static final String ADDR_PREFIX = "0x";
    private static final String AION_PREFIX = "a0";
    private static final int IMPORT_LIMIT = 100;
    private static String KEYSTORE_PATH;
    private static Path PATH;

    static {
        String storageDir = System.getProperty("local.storage.dir");
        if (storageDir == null || storageDir.equalsIgnoreCase("")) {
            storageDir = System.getProperty("user.dir");
        }
        KEYSTORE_PATH = storageDir + "/keystore";
        PATH = Paths.get(KEYSTORE_PATH);
    }

    public static String create(String password) {
        return create(password, ECKeyFac.inst().create());
    }

    public static String create(String password, ECKey key) {

        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxr-----");
        FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);

        if (!Files.exists(PATH)) {
            try {
                Files.createDirectory(PATH, attr);
            } catch (IOException e) {
                LOG.error("keystore folder create failed!");
                return "";
            }
        }

        String address = ByteUtil.toHexString(key.getAddress());
        if (exist(address)) {
            return ADDR_PREFIX;
        } else {
            byte[] content = new KeystoreFormat().toKeystore(key, password);
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            df.setTimeZone(TimeZone.getTimeZone("UTC"));
            String iso_date = df.format(new Date(System.currentTimeMillis()));
            String fileName = "UTC--" + iso_date + "--" + address;
            try {
                Path keyFile = PATH.resolve(fileName);
                if (!Files.exists(keyFile)) keyFile = Files.createFile(keyFile, attr);
                String path = keyFile.toString();
                FileOutputStream fos = new FileOutputStream(path);
                fos.write(content);
                fos.close();
                return StringUtils.toJsonHex(address);
            } catch (IOException e) {
                LOG.error("fail to create keystore");
                return ADDR_PREFIX;
            }
        }
    }

    public static Map<AionAddress, ByteArrayWrapper> exportAccount(
            Map<AionAddress, String> account) {
        if (account == null) {
            throw new NullPointerException();
        }

        Map<AionAddress, ByteArrayWrapper> res = new HashMap<>();
        for (Map.Entry<AionAddress, String> entry : account.entrySet()) {
            ECKey eckey = Keystore.getKey(entry.getKey().toString(), entry.getValue());
            if (eckey != null) {
                res.put(entry.getKey(), ByteArrayWrapper.wrap(eckey.getPrivKeyBytes()));
            }
        }

        return res;
    }

    public static Map<AionAddress, ByteArrayWrapper> backupAccount(
            Map<AionAddress, String> account) {
        if (account == null) {
            throw new NullPointerException();
        }

        List<File> files = org.aion.util.file.File.getFiles(PATH);
        if (files == null) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("No key file been stored in the kernel.");
            }
            return new java.util.HashMap<>();
        }

        List<File> matchedFile =
                files.parallelStream()
                        .filter(
                                file ->
                                        account.entrySet()
                                                .parallelStream()
                                                .anyMatch(
                                                        ac ->
                                                                file.getName()
                                                                        .contains(
                                                                                ac.getKey()
                                                                                        .toString())))
                        .collect(Collectors.toList());

        Map<AionAddress, ByteArrayWrapper> res = new HashMap<>();
        for (File file : matchedFile) {
            try {
                String[] frags = file.getName().split("--");
                if (frags.length == 3) {
                    if (frags[2].startsWith(AION_PREFIX)) {
                        AionAddress addr = AddressUtils.wrapAddress(frags[2]);
                        byte[] content = Files.readAllBytes(file.toPath());

                        String pw = account.get(addr);
                        if (pw != null) {
                            ECKey key = KeystoreFormat.fromKeystore(content, pw);
                            if (key != null) {
                                res.put(addr, ByteArrayWrapper.wrap(content));
                            }
                        }
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Wrong address format: {}", frags[2]);
                        }
                    }
                }
            } catch (IOException e) {
                LOG.error("backupAccount exception {}", e.toString());
            }
        }

        return res;
    }

    public static String[] list() {
        return addAddrs(org.aion.util.file.File.getFiles(PATH)).toArray(new String[0]);
    }

    private static List<String> addAddrs(List<File> files) {
        List<String> addresses = new ArrayList<>();
        files.forEach(
                (file) -> {
                    String[] frags = file.getName().split("--");
                    if (frags.length == 3) {
                        if (frags[2].startsWith(AION_PREFIX)) {
                            addresses.add(StringUtils.toJsonHex(frags[2]));
                        } else {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Wrong address format: {}", frags[2]);
                            }
                        }
                    }
                });
        return addresses;
    }

    /**
     * Returns a sorted list of account addresses
     *
     * @return address represent by String as a List
     */
    public static List<String> accountsSorted() {
        List<File> files = org.aion.util.file.File.getFiles(PATH);
        files.sort(COMPARE);
        return addAddrs(files);
    }

    public static ECKey getKey(String _address, String _password) {
        if (_address.startsWith(ADDR_PREFIX)) {
            _address = _address.substring(2);
        }

        ECKey key = null;
        if (_address.startsWith(AION_PREFIX)) {
            List<File> files = org.aion.util.file.File.getFiles(PATH);
            for (File file : files) {
                if (HEX_64.matcher(_address).find() && file.getName().contains(_address)) {
                    try {
                        byte[] content = Files.readAllBytes(file.toPath());
                        key = KeystoreFormat.fromKeystore(content, _password);

                    } catch (IOException e) {
                        LOG.error("getKey exception! {}", e.toString());
                    }
                    break;
                }
            }
        }
        return key;
    }

    /**
     * Returns true if the address _address exists, false otherwise.
     *
     * @param _address the address whose existence is to be tested.
     * @return true only if _address exists.
     */
    public static boolean exist(String _address) {
        if (_address.startsWith(ADDR_PREFIX)) {
            _address = _address.substring(2);
        }

        boolean flag = false;
        if (_address.startsWith(AION_PREFIX)) {
            List<File> files = org.aion.util.file.File.getFiles(PATH);
            for (File file : files) {
                if (HEX_64.matcher(_address).find() && file.getName().contains(_address)) {
                    flag = true;
                    break;
                }
            }
        }
        return flag;
    }

    public static Set<String> importAccount(Map<String, String> importKey) {
        if (importKey == null) {
            throw new NullPointerException();
        }

        Set<String> rtn = new HashSet<>();
        int count = 0;
        for (Map.Entry<String, String> keySet : importKey.entrySet()) {
            if (count < IMPORT_LIMIT) {
                ECKey key =
                        KeystoreFormat.fromKeystore(Hex.decode(keySet.getKey()), keySet.getValue());
                if (key != null) {
                    String address = Keystore.create(keySet.getValue(), key);
                    if (!address.equals(ADDR_PREFIX)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                    "The private key was imported, the address is {}",
                                    keySet.getKey());
                        }
                    } else {
                        LOG.error(
                                "Failed to import the private key {}. Already exists?",
                                keySet.getKey());
                        // only return the failed import privateKey.
                        rtn.add(keySet.getKey());
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(
                            "The account import limit was reached, the address didn't import into keystore {}",
                            keySet.getKey());
                }
                rtn.add(keySet.getKey());
            }
            count++;
        }

        return rtn;
    }

    /*
     * Test method. Don't use it for the code dev.
     */
    static File getAccountFile(String address, String password) {
        List<File> files = org.aion.util.file.File.getFiles(PATH);
        if (files == null) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("No key file been stored in the kernel.");
            }
            return null;
        }

        Optional<File> matchedFile =
                files.parallelStream().filter(file -> file.getName().contains(address)).findFirst();

        if (matchedFile.isPresent()) {
            byte[] content = new byte[0];
            try {
                content = Files.readAllBytes(matchedFile.get().toPath());
            } catch (IOException e) {
                LOG.error("getAccountFile exception! {}", e.toString());
            }

            if (null != KeystoreFormat.fromKeystore(content, password)) {
                return matchedFile.get();
            }
        }

        return null;
    }

    public static void setKeystorePath(String path) {
        KEYSTORE_PATH = path;
        PATH = Paths.get(KEYSTORE_PATH);
    }

    public static String getKeystorePath() {
        return KEYSTORE_PATH;
    }
}
