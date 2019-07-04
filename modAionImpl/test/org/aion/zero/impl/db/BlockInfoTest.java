package org.aion.zero.impl.db;

import static com.google.common.truth.Truth.assertThat;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.aion.crypto.HashUtil;
import org.aion.util.bytes.ByteUtil;
import org.aion.util.types.ByteArrayWrapper;
import org.junit.Test;

/** Test suite for {@link org.aion.zero.impl.db.AionBlockStore.BlockInfo} serialization */
public class BlockInfoTest {

    private byte[] DEFAULT_HASH = HashUtil.h256("hello world".getBytes());

    private byte[] OLD_BLOCKINFO_DATA_1 =
            ByteUtil.hexStringToBytes(
                    "0xaced0005737200136a6176612e7574696c2e41727261794c6973747881d21d99c7619d03000149000473697a65787000000001770400000001737200276f72672e61696f6e2e64622e61302e41696f6e426c6f636b53746f726524426c6f636b496e666f650530b92d86765f0200035a00096d61696e436861696e4c000e63756d6d446966666963756c74797400164c6a6176612f6d6174682f426967496e74656765723b5b0004686173687400025b42787001737200146a6176612e6d6174682e426967496e74656765728cfc9f1fa93bfb1d030006490008626974436f756e744900096269744c656e67746849001366697273744e6f6e7a65726f427974654e756d49000c6c6f776573745365744269744900067369676e756d5b00096d61676e697475646571007e0004787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b0200007870fffffffffffffffffffffffefffffffe00000001757200025b42acf317f8060854e00200007870000000035a7174787571007e000900000020bfd84d03d8726c6b3b9221d2cce051b94900a2b1dd6186838a2bd9c47853e7a878");

    @Test
    public void testBlockInfoSerialization() {
        AionBlockStore.BlockInfo info =
                new AionBlockStore.BlockInfo(DEFAULT_HASH, BigInteger.ONE, true);

        byte[] serialized =
                AionBlockStore.BLOCK_INFO_SERIALIZER.serialize(Collections.singletonList(info));
        System.out.println("serialized: " + new ByteArrayWrapper(serialized));

        List<AionBlockStore.BlockInfo> deserializedBlockInfos =
                AionBlockStore.BLOCK_INFO_SERIALIZER.deserialize(serialized);
        assertThat(deserializedBlockInfos.size()).isEqualTo(1);

        AionBlockStore.BlockInfo deserializedInfo = deserializedBlockInfos.get(0);

        assertThat(deserializedInfo.getCummDifficulty()).isEqualTo(info.getCummDifficulty());
        assertThat(deserializedInfo.getHash()).isEqualTo(info.getHash());
        assertThat(deserializedInfo.isMainChain()).isEqualTo(info.isMainChain());
    }

    @Test
    public void testBlockInfoMultipleSerialization() {
        AionBlockStore.BlockInfo info =
                new AionBlockStore.BlockInfo(DEFAULT_HASH, BigInteger.ONE, true);
        AionBlockStore.BlockInfo info2 =
                new AionBlockStore.BlockInfo(HashUtil.h256(DEFAULT_HASH), BigInteger.TWO, false);

        byte[] serialized =
                AionBlockStore.BLOCK_INFO_SERIALIZER.serialize(Arrays.asList(info, info2));
        System.out.println("serialized: " + new ByteArrayWrapper(serialized));

        // deserialized
        List<AionBlockStore.BlockInfo> deserializedBlockInfos =
                AionBlockStore.BLOCK_INFO_SERIALIZER.deserialize(serialized);

        AionBlockStore.BlockInfo dInfo1 = deserializedBlockInfos.get(0);

        assertThat(dInfo1.getCummDifficulty()).isEqualTo(info.getCummDifficulty());
        assertThat(dInfo1.getHash()).isEqualTo(info.getHash());
        assertThat(dInfo1.isMainChain()).isEqualTo(info.isMainChain());

        AionBlockStore.BlockInfo dInfo2 = deserializedBlockInfos.get(1);

        assertThat(dInfo2.getCummDifficulty()).isEqualTo(info2.getCummDifficulty());
        assertThat(dInfo2.getHash()).isEqualTo(info2.getHash());
        assertThat(dInfo2.isMainChain()).isEqualTo(info2.isMainChain());
    }

    @Test
    public void testBlockInfoMigrationSerialization() {
        byte[] serialized = OLD_BLOCKINFO_DATA_1;
        List<AionBlockStore.BlockInfo> des =
                AionBlockStore.BLOCK_INFO_SERIALIZER.deserialize(serialized);
        assertThat(des.size()).isEqualTo(1);

        AionBlockStore.BlockInfo info = des.get(0);
        assertThat(info.getCummDifficulty()).isEqualTo(BigInteger.valueOf(5927284));
        assertThat(
                        Arrays.equals(
                                info.getHash(),
                                ByteUtil.hexStringToBytes(
                                        "0xbfd84d03d8726c6b3b9221d2cce051b94900a2b1dd6186838a2bd9c47853e7a8")))
                .isTrue();
        assertThat(info.isMainChain()).isTrue();
    }
}
