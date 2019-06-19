package org.aion.zero.impl.db;

import static java.math.BigInteger.ZERO;
import static org.aion.crypto.HashUtil.shortHash;

import com.google.common.annotations.VisibleForTesting;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.aion.interfaces.db.ByteArrayKeyValueDatabase;
import org.aion.log.AionLoggerFactory;
import org.aion.log.LogEnum;
import org.aion.mcf.db.AbstractPowBlockstore;
import org.aion.mcf.ds.DataSourceArray;
import org.aion.mcf.ds.ObjectDataSource;
import org.aion.mcf.ds.Serializer;
import org.aion.rlp.RLP;
import org.aion.rlp.RLPElement;
import org.aion.rlp.RLPList;
import org.aion.util.bytes.ByteUtil;
import org.aion.util.conversions.Hex;
import org.aion.zero.impl.types.AionBlock;
import org.aion.zero.types.A0BlockHeader;
import org.aion.zero.types.IAionBlock;
import org.slf4j.Logger;

public class AionBlockStore extends AbstractPowBlockstore<AionBlock, A0BlockHeader> {

    private static final Logger LOG = AionLoggerFactory.getLogger(LogEnum.DB.name());
    private static final Logger LOG_CONS = AionLoggerFactory.getLogger(LogEnum.CONS.name());

    protected ReadWriteLock lock = new ReentrantReadWriteLock();

    private DataSourceArray<List<BlockInfo>> index;
    private ObjectDataSource<AionBlock> blocks;

    private boolean checkIntegrity = true;

    private Deque<IAionBlock> branchingBlk = new ArrayDeque<>(),
            preBranchingBlk = new ArrayDeque<>();
    private long branchingLevel;

    public AionBlockStore(ByteArrayKeyValueDatabase index, ByteArrayKeyValueDatabase blocks) {
        init(index, blocks);
    }

    public AionBlockStore(
            ByteArrayKeyValueDatabase index,
            ByteArrayKeyValueDatabase blocks,
            boolean checkIntegrity) {
        this(index, blocks);
        this.checkIntegrity = checkIntegrity;
    }

    private void init(ByteArrayKeyValueDatabase index, ByteArrayKeyValueDatabase blocks) {

        this.index = new DataSourceArray<>(new ObjectDataSource<>(index, BLOCK_INFO_SERIALIZER));

        this.blocks =
                new ObjectDataSource<>(
                        blocks,
                        new Serializer<AionBlock, byte[]>() {
                            @Override
                            public byte[] serialize(AionBlock block) {
                                return block.getEncoded();
                            }

                            @Override
                            public AionBlock deserialize(byte[] bytes) {
                                return new AionBlock(bytes);
                            }
                        });
    }

    public AionBlock getBestBlock() {
        lock.readLock().lock();

        try {
            long maxLevel = getMaxNumber();
            if (maxLevel < 0) {
                return null;
            }

            AionBlock bestBlock = getChainBlockByNumber(maxLevel);
            if (bestBlock != null) {
                return bestBlock;
            }

            while (bestBlock == null) {
                --maxLevel;
                bestBlock = getChainBlockByNumber(maxLevel);
            }

            return bestBlock;
        } finally {
            lock.readLock().unlock();
        }
    }

    public byte[] getBlockHashByNumber(long blockNumber) {
        lock.readLock().lock();

        try {
            if (blockNumber < 0L || blockNumber >= index.size()) {
                return null;
            }

            List<BlockInfo> blockInfos = index.get(blockNumber);

            for (BlockInfo blockInfo : blockInfos) {
                if (blockInfo.isMainChain()) {
                    return blockInfo.getHash();
                }
            }

            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void flush() {
        lock.writeLock().lock();
        try {
            blocks.flush();
            index.flush();
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void saveBlock(AionBlock block, BigInteger cummDifficulty, boolean mainChain) {
        lock.writeLock().lock();
        try {
            addInternalBlock(block, cummDifficulty, mainChain);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** @implNote The method calling this method must handle the locking. */
    private void addInternalBlock(AionBlock block, BigInteger cummDifficulty, boolean mainChain) {
        long blockNumber = block.getNumber();
        List<BlockInfo> blockInfos =
                blockNumber >= index.size() ? new ArrayList<>() : index.get(blockNumber);

        // if the blocks are added out of order, the size will be updated without changing the index
        // value
        // useful for concurrency testing and potential parallel sync
        if (blockInfos == null) {
            LOG.error(
                    "Null block information found at " + blockNumber + " when data should exist.");
            blockInfos = new ArrayList<>();
        }

        if (mainChain) {
            for (BlockInfo blockInfo : blockInfos) {
                blockInfo.setMainChain(false);
            }
        }

        blockInfos.add(new BlockInfo(block.getHash(), cummDifficulty, mainChain));

        blocks.put(block.getHash(), block);
        index.set(block.getNumber(), blockInfos);
    }

    public List<Map.Entry<AionBlock, Map.Entry<BigInteger, Boolean>>> getBlocksByNumber(
            long number) {
        lock.readLock().lock();

        try {
            List<Map.Entry<AionBlock, Map.Entry<BigInteger, Boolean>>> result = new ArrayList<>();

            if (number >= index.size()) {
                return result;
            }

            List<BlockInfo> blockInfos = index.get(number);

            for (BlockInfo blockInfo : blockInfos) {

                byte[] hash = blockInfo.getHash();
                AionBlock block = blocks.get(hash);

                result.add(
                        Map.entry(
                                block,
                                Map.entry(blockInfo.getCummDifficulty(), blockInfo.mainChain)));
            }

            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public AionBlock getChainBlockByNumber(long number) {
        lock.readLock().lock();

        try {
            long size = index.size();
            if (number < 0L || number >= size) {
                return null;
            }

            List<BlockInfo> blockInfos = index.get(number);

            if (blockInfos == null) {
                return null;
            }

            for (BlockInfo blockInfo : blockInfos) {
                if (blockInfo.isMainChain()) {
                    byte[] hash = blockInfo.getHash();
                    AionBlock block = blocks.get(hash);
                    if (block != null) {
                        block.setCumulativeDifficulty(blockInfo.cummDifficulty);
                        return block;
                    }
                }
            }

            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * @implNote method use for the CLI tooling
     * @param number block number
     * @return list of blocks in the given block level.
     */

    List<AionBlock> getAllChainBlockByNumber(long number) {
        lock.readLock().lock();

        try {
            long size = index.size();
            if (number < 0L || number >= size) {
                return null;
            }

            List<BlockInfo> blockInfos = index.get(number);

            if (blockInfos == null) {
                return null;
            }

            List<AionBlock> blockList = new ArrayList<>();
            for (BlockInfo blockInfo : blockInfos) {
                AionBlock b = blocks.get(blockInfo.getHash());
                if (blockInfo.isMainChain()) {
                    b.setMainChain();
                }

                b.setCumulativeDifficulty(blockInfo.cummDifficulty);
                blockList.add(b);
            }

            return blockList;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Returns a range of main chain blocks.
     *
     * @param first the height of the first block in the requested range; this block must exist in
     *     the blockchain and be above the genesis to return a non-null output
     * @param last the height of the last block in the requested range; when requesting blocks in
     *     ascending order the last element will be substituted with the best block if its height is
     *     above the best known block
     * @return a list containing consecutive main chain blocks with heights ranging according to the
     *     given parameters; or {@code null} in case of errors or illegal request
     * @apiNote The blocks must be added to the list in the order that they are requested. If {@code
     *     first > last} the blocks are returned in descending order of their height, otherwise when
     *     {@code first < last} the blocks are returned in ascending order of their height.
     */
    public List<AionBlock> getBlocksByRange(long first, long last) {
        if (first <= 0L) {
            return null;
        }

        lock.readLock().lock();

        try {
            AionBlock block = getChainBlockByNumber(first);
            if (block == null) {
                // invalid request
                return null;
            }

            if (first == last) {
                return List.of(block);
            } else if (first > last) { // first is highest -> can query directly by parent hash
                List<AionBlock> blocks = new ArrayList<>();
                blocks.add(block);

                for (long i = first - 1; i >= (last > 0 ? last : 1); i--) {
                    block = getBlockByHash(block.getParentHash());
                    if (block == null) {
                        // the block should have been stored but null was returned above
                        LOG.error(
                                "Encountered a kernel database corruption: cannot find block at level {} in data store.",
                                i);
                        LOG.error(
                            " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", i - 1);
                        return null; // stops at any invalid data
                    } else {
                        blocks.add(block);
                    }
                }
                return blocks;
            } else { // last is highest
                LinkedList<AionBlock> blocks = new LinkedList<>();
                AionBlock lastBlock = getChainBlockByNumber(last);

                if (lastBlock == null) { // assuming height was above best block
                    // attempt to get best block
                    lastBlock = getBestBlock();
                    if (lastBlock == null) {
                        LOG.error(
                                "Encountered a kernel database corruption: cannot find best block in data store.");
                        LOG.error("Please reboot your node to trigger automatic database recovery by the kernel." );
                        return null;
                    } else if (last < lastBlock.getNumber()) {
                        // the block should have been stored but null was returned above
                        LOG.error(
                                "Encountered a kernel database corruption: cannot find block at level {} in data store.",
                                last);
                        LOG.error(
                            " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", last - 1);
                        return null;
                    }
                }
                // the block was not null
                // or  it was higher than the best block and replaced with the best block

                // building existing range
                blocks.addFirst(lastBlock);
                long newLast = lastBlock.getNumber();
                for (long i = newLast - 1; i > first; i--) {
                    lastBlock = getBlockByHash(lastBlock.getParentHash());
                    if (lastBlock == null) {
                        LOG.error(
                                "Encountered a kernel database corruption: cannot find block at level {} in block data store.",
                                i);
                        LOG.error(
                            " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", i - 1);
                        return null;
                    } else {
                        // always adding at the beginning of the list
                        // to return the expected order of blocks
                        blocks.addFirst(lastBlock);
                    }
                }

                // adding the initial block
                blocks.addFirst(block);
                return blocks;
            }
        } finally {
            lock.readLock().unlock();
        }
    }

    @SuppressWarnings("Duplicates")
    public Map.Entry<AionBlock, BigInteger> getChainBlockByNumberWithTotalDifficulty(long number) {
        lock.readLock().lock();

        try {
            if (number < 0L || number >= index.size()) {
                return null;
            }

            List<BlockInfo> blockInfos = index.get(number);
            if (blockInfos == null) {
                LOG.error(
                        "Encountered a kernel database corruption: cannot find blockInfos at level {} in index data store.",
                        number);
                LOG.error(
                    " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", number - 1);
                return null;
            }

            for (BlockInfo blockInfo : blockInfos) {
                if (blockInfo.isMainChain()) {
                    byte[] hash = blockInfo.getHash();
                    return Map.entry(blocks.get(hash), blockInfo.getCummDifficulty());
                }
            }

            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public AionBlock getBlockByHash(byte[] hash) {
        lock.readLock().lock();
        try {
            return blocks.get(hash);
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public boolean isBlockExist(byte[] hash) {
        return getBlockByHash(hash) != null;
    }

    /** Retrieve the total difficulty given the block hash.
     *
     * @param hash the block hash
     * @return 0 when the hash info is not matched or database corruption. Otherwise, return the total difficulty
     * info stored in the index database.
     */

    @Override
    public BigInteger getTotalDifficultyForHash(byte[] hash) {
        lock.readLock().lock();

        try {
            IAionBlock block = this.getBlockByHash(hash);
            if (block == null) {
                return ZERO;
            }

            List<BlockInfo> blockInfos = index.get(block.getNumber());
            if (blockInfos == null) {
                LOG.error(
                    "Encountered a kernel database corruption: cannot find blockInfos at level {} in index data store.",
                    block.getNumber());
                LOG.error(
                    " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", block.getNumber() - 1);
                return ZERO;
            }

            for (BlockInfo blockInfo : blockInfos) {
                if (Arrays.equals(blockInfo.getHash(), hash)) {
                    return blockInfo.getCummDifficulty();
                }
            }

            LOG.error(
                "Encountered a kernel database corruption: cannot find the matched hash of blockInfos at level {} in index data store.",
                block.getNumber());
            LOG.error(
                " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", block.getNumber() - 1);
            return ZERO;
        } finally {
            lock.readLock().unlock();
        }
    }

    /** Retrieve the total difficulty from the index database.
     * Try to look at any mainchain block info in the highest level. If can't find it, then go backward
     * to find the highest mainchain block info. after backward 128 blocks still can't find the mainchain
     * block, then we throw the exception for notice user the database corrupt or branch too deep.
     * @exception IllegalStateException reflect the database corrupt or mainchain branch goes too deep.
     * @return the total difficulty of the highest block in the mainchain.
     */

    @Override
    public BigInteger getTotalDifficulty() {
        lock.readLock().lock();

        try {
            long maxNumber = getMaxNumber();

            List<BlockInfo> blockInfos = index.get(maxNumber);
            if (blockInfos != null && !blockInfos.isEmpty()) {
                for (BlockInfo blockInfo : blockInfos) {
                    if (blockInfo.isMainChain()) {
                        return blockInfo.getCummDifficulty();
                    }
                }
            }

            // Can't find the mainchain blockInfo in the highest block index. Looking backward to see
            // have any mainchain block info in the previous levels.
            int depth = 0;
            while (depth < 128) {
                --maxNumber;
                List<BlockInfo> infos = getBlockInfoForLevel(maxNumber);

                for (BlockInfo blockInfo : infos) {
                    if (blockInfo.isMainChain()) {
                        return blockInfo.getCummDifficulty();
                    }
                }
                ++depth;
            }

            LOG.error(
                    "Encountered a kernel database corruption: cannot find blockInfos at level {} in index data store. "
                        + "Or the branch is too deep, it should not happens. "
                        + "Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}",
                    maxNumber,
                    maxNumber - 1);

            throw new IllegalStateException("Index DB corruption or branch too deep.");
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public long getMaxNumber() {
        lock.readLock().lock();

        try {
            return index.size() - 1L;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<byte[]> getListHashesEndWith(byte[] hash, long number) {
        lock.readLock().lock();

        try {
            List<AionBlock> blocks = getListBlocksEndWith(hash, number);
            List<byte[]> hashes = new ArrayList<>(blocks.size());

            for (IAionBlock b : blocks) {
                hashes.add(b.getHash());
            }

            return hashes;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<A0BlockHeader> getListHeadersEndWith(byte[] hash, long qty) {
        lock.readLock().lock();
        try {
            List<AionBlock> blocks = getListBlocksEndWith(hash, qty);
            List<A0BlockHeader> headers = new ArrayList<>(blocks.size());

            for (IAionBlock b : blocks) {
                headers.add(b.getHeader());
            }

            return headers;
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public List<AionBlock> getListBlocksEndWith(byte[] hash, long qty) {
        lock.readLock().lock();
        try {
            return getListBlocksEndWithInner(hash, qty);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** @implNote The method calling this method must handle the locking. */
    private List<AionBlock> getListBlocksEndWithInner(byte[] hash, long qty) {
        // locks acquired by calling method
        AionBlock block = this.blocks.get(hash);

        if (block == null) {
            return new ArrayList<>();
        }

        List<AionBlock> blocks = new ArrayList<>((int) qty);

        for (int i = 0; i < qty; ++i) {
            blocks.add(block);
            block = this.blocks.get(block.getParentHash());
            if (block == null) {
                break;
            }
        }

        return blocks;
    }

    @Override
    public void reBranch(AionBlock forkBlock) {
        lock.writeLock().lock();

        try {
            IAionBlock bestBlock = getBestBlock();

            long currentLevel = Math.max(bestBlock.getNumber(), forkBlock.getNumber());

            // 1. First ensure that you are one the save level
            IAionBlock forkLine = forkBlock;
            if (forkBlock.getNumber() > bestBlock.getNumber()) {
                branchingLevel = currentLevel;

                while (currentLevel > bestBlock.getNumber()) {
                    List<BlockInfo> blocks = getBlockInfoForLevel(currentLevel);
                    BlockInfo blockInfo = getBlockInfoForHash(blocks, forkLine.getHash());
                    if (blockInfo != null) {
                        blockInfo.setMainChain(true);
                        setBlockInfoForLevel(currentLevel, blocks);

                        // For collecting branching blocks
                        branchingBlk.push(getBlockByHash(blockInfo.getHash()));
                    } else {
                        LOG.error(
                                "Encountered a kernel database corruption: cannot find block with fork line hash {} at the level {} in index data store.",
                                ByteUtil.toHexString(forkLine.getHash()),
                                currentLevel);
                        LOG.error("Please reboot your node to trigger automatic database recovery by the kernel." );
                    }
                    forkLine = getBlockByHash(forkLine.getParentHash());
                    --currentLevel;
                }
            }

            IAionBlock bestLine = bestBlock;
            if (bestBlock.getNumber() > forkBlock.getNumber()) {

                while (currentLevel > forkBlock.getNumber()) {

                    List<BlockInfo> blocks = getBlockInfoForLevel(currentLevel);
                    BlockInfo blockInfo = getBlockInfoForHash(blocks, bestLine.getHash());
                    if (blockInfo != null) {
                        blockInfo.setMainChain(false);
                        setBlockInfoForLevel(currentLevel, blocks);

                        // For collecting prebranching blocks
                        preBranchingBlk.push(getBlockByHash(blockInfo.getHash()));
                    } else {
                        LOG.error(
                            "Encountered a kernel database corruption: cannot find block with best line hash {} at the level {} in index data store.",
                            ByteUtil.toHexString(forkLine.getHash()),
                            currentLevel);
                        LOG.error("Please reboot your node to trigger automatic database recovery by the kernel." );
                    }
                    bestLine = getBlockByHash(bestLine.getParentHash());
                    --currentLevel;
                }
            }

            // 2. Loop back on each level until common block
            loopBackToCommonBlock(bestLine, forkLine);

            logBranchingDetails();

        } finally {
            lock.writeLock().unlock();
        }
    }

    private void logBranchingDetails() {
        if (branchingLevel > 0 && LOG_CONS.isDebugEnabled()) {
            LOG_CONS.debug("Branching details start: level[{}]", branchingLevel);

            LOG_CONS.debug("===== Block details before branch =====");
            while (!preBranchingBlk.isEmpty()) {
                IAionBlock blk = preBranchingBlk.pop();
                LOG_CONS.debug("blk: {}", blk.toString());
            }

            LOG_CONS.debug("===== Block details after branch =====");
            while (!branchingBlk.isEmpty()) {
                IAionBlock blk = branchingBlk.pop();
                LOG_CONS.debug("blk: {}", blk.toString());
            }

            LOG_CONS.debug("Branching details end");
        }

        // reset branching block details
        branchingLevel = 0;
        branchingBlk.clear();
        preBranchingBlk.clear();
    }

    /** @implNote The method calling this method must handle the locking. */
    private void loopBackToCommonBlock(IAionBlock bestLine, IAionBlock forkLine) {
        long currentLevel = bestLine.getNumber();

        if (forkLine.getNumber() != currentLevel) {
            LOG.error("Illegal parameters for loopBackToCommonBlock method.");
            return;
        }

        while (!bestLine.isEqual(forkLine)) {
            List<BlockInfo> levelBlocks = getBlockInfoForLevel(currentLevel);
            BlockInfo bestInfo = getBlockInfoForHash(levelBlocks, bestLine.getHash());
            if (bestInfo != null) {
                bestInfo.setMainChain(false);
                setBlockInfoForLevel(currentLevel, levelBlocks);

                // For collecting preBranching blocks
                preBranchingBlk.push(getBlockByHash(bestInfo.getHash()));
            } else {
                LOG.error(
                    "Encountered a kernel database corruption: cannot find block with best line hash {} at the level {} in index data store.",
                    ByteUtil.toHexString(forkLine.getHash()),
                    currentLevel);
                LOG.error("Please reboot your node to trigger automatic database recovery by the kernel." );
            }

            BlockInfo forkInfo = getBlockInfoForHash(levelBlocks, forkLine.getHash());
            if (forkInfo != null) {
                forkInfo.setMainChain(true);
                setBlockInfoForLevel(currentLevel, levelBlocks);

                // For collecting branching blocks
                branchingBlk.push(getBlockByHash(forkInfo.getHash()));
            } else {
                LOG.error(
                    "Encountered a kernel database corruption: cannot find block with fork line hash {} at the level {} in index data store.",
                    ByteUtil.toHexString(forkLine.getHash()),
                    currentLevel);
                LOG.error("Please reboot your node to trigger automatic database recovery by the kernel." );
            }

            bestLine = getBlockByHash(bestLine.getParentHash());
            forkLine = getBlockByHash(forkLine.getParentHash());

            --currentLevel;
        }

        branchingLevel -= currentLevel;

        if (LOG_CONS.isInfoEnabled()) {
            LOG_CONS.info(
                    "branching: common block = {}/{}",
                    forkLine.getNumber(),
                    Hex.toHexString(forkLine.getHash()));
        }
    }

    @Override
    public void revert(long previousLevel) {
        lock.writeLock().lock();

        try {
            IAionBlock bestBlock = getBestBlock();

            long currentLevel = bestBlock.getNumber();

            // ensure that the given level is lower than current
            if (previousLevel >= currentLevel) {
                return;
            }

            // walk back removing blocks greater than the given level value
            IAionBlock bestLine = bestBlock;
            while (currentLevel > previousLevel) {

                // remove all the blocks at that level
                List<BlockInfo> currentLevelBlocks = getBlockInfoForLevel(currentLevel);
                if (currentLevelBlocks == null || currentLevelBlocks.isEmpty()) {
                    blocks.delete(bestLine.getHash());
                    LOG.error(
                            "Null block information found at "
                                    + currentLevel
                                    + " when information should exist.");

                    LOG.error("Please reboot your node to trigger automatic database recovery by the kernel." );
                } else {
                    for (BlockInfo bk_info : currentLevelBlocks) {
                        blocks.delete(bk_info.getHash());
                    }
                }

                // remove the level
                index.remove(currentLevel);
                if (bestLine != null) {
                    bestLine = getBlockByHash(bestLine.getParentHash());
                } else {
                    // attempt to find another block at the parent level
                    bestLine = getChainBlockByNumber(currentLevel - 1);
                }
                --currentLevel;
            }

            if (bestLine == null) {
                LOG.error(
                        "Block at level #"
                                + previousLevel
                                + " is null. Reverting further back may be required.");
                LOG.error(
                    " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", previousLevel - 1);
            } else {
                // update the main chain based on difficulty, if needed
                List<BlockInfo> blocks = getBlockInfoForLevel(previousLevel);
                BlockInfo blockInfo = getBlockInfoForHash(blocks, bestLine.getHash());

                // no side chains at this level
                if (blocks.size() == 1 && blockInfo != null) {
                    if (!blockInfo.isMainChain()) {
                        blockInfo.setMainChain(true);
                        setBlockInfoForLevel(previousLevel, blocks);
                    }
                } else {
                    if (blockInfo == null) {
                        LOG.error(
                                "Null block information found at "
                                        + previousLevel
                                        + " when data should exist. "
                                        + "Rebuilding information.");

                        // recreate missing block info
                        blockInfo = new BlockInfo(bestLine.getHash(), getTotalDifficultyForHash(bestLine.getParentHash())
                            .add(bestLine.getHeader().getDifficultyBI()), true);
                        blocks.add(blockInfo);
                    }

                    // check for max total difficulty
                    BlockInfo maxTDInfo = blockInfo;
                    for (BlockInfo info : blocks) {
                        if (info.getCummDifficulty().compareTo(maxTDInfo.getCummDifficulty()) > 0) {
                            maxTDInfo = info;
                        }
                    }

                    // 2. Loop back on each level until common block
                    IAionBlock forkLine = getBlockByHash(maxTDInfo.getHash());
                    loopBackToCommonBlock(bestLine, forkLine);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void pruneAndCorrect() {
        lock.writeLock().lock();

        try {
            IAionBlock block = getBestBlock();
            long initialLevel = block.getNumber();
            long level = initialLevel;

            // top down pruning of nodes on side chains
            while (level > 0) {
                pruneSideChains(block);
                block = getBlockByHash(block.getParentHash());
                if (block == null) {
                    LOG.error(
                            "Block #"
                                    + (level - 1)
                                    + " missing from the database. "
                                    + "Cannot proceed with block pruning and total difficulty updates.");
                    LOG.error(
                        " Please shutdown the kernel and rollback the database by executing:\t./aion.sh -n <network> -r {}", level - 1);
                }
                level = block.getNumber();
            }

            // prune genesis
            pruneSideChains(block);

            // bottom up repair of information
            // initial TD set to genesis TD
            BigInteger parentTotalDifficulty = block.getHeader().getDifficultyBI();
            level = 1;
            while (level <= initialLevel) {
                parentTotalDifficulty = correctTotalDifficulty(level, parentTotalDifficulty);
                LOG.info(
                        "Updated total difficulty on level "
                                + level
                                + " to "
                                + parentTotalDifficulty
                                + ".");
                level++;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** @implNote The method calling this method must handle the locking. */
    private void pruneSideChains(IAionBlock block) {
        // current level
        long level = block.getNumber();
        byte[] blockHash = block.getHash();

        LOG.info("Pruning side chains on level " + level + ".");

        List<BlockInfo> levelBlocks = getBlockInfoForLevel(level);
        BlockInfo blockInfo = getBlockInfoForHash(levelBlocks, blockHash);

        // check if info was there
        while (blockInfo != null) {
            levelBlocks.remove(blockInfo);
            // checking multiple times due to the duplicate info issue
            blockInfo = getBlockInfoForHash(levelBlocks, blockHash);
        }

        // deleting incorrect parallel blocks
        for (BlockInfo wrongBlock : levelBlocks) {
            blocks.delete(wrongBlock.getHash());
        }

        // set new block info with total difficulty = block difficulty
        blockInfo = new BlockInfo(blockHash, block.getHeader().getDifficultyBI(), true);

        levelBlocks = new ArrayList<>();
        levelBlocks.add(blockInfo);

        setBlockInfoForLevel(level, levelBlocks);
    }

    /** @implNote The method calling this method must handle the locking. */
    private BigInteger correctTotalDifficulty(long level, BigInteger parentTotalDifficulty) {
        List<BlockInfo> levelBlocks = getBlockInfoForLevel(level);

        if (levelBlocks.size() != 1) {
            // something went awry
            LOG.error(
                    "Cannot proceed with total difficulty updates. Previous updates have been overwritten.");
            return null;
        } else {
            // correct block info
            BlockInfo blockInfo = levelBlocks.remove(0);
            // total difficulty previously set to block difficulty
            levelBlocks.add(new BlockInfo(blockInfo.getHash(), blockInfo.getCummDifficulty().add(parentTotalDifficulty), blockInfo.isMainChain()));
            setBlockInfoForLevel(level, levelBlocks);

            return blockInfo.getCummDifficulty();
        }
    }

    public BigInteger correctIndexEntry(AionBlock block, BigInteger parentTotalDifficulty) {
        lock.writeLock().lock();

        try {
            long blockNumber = block.getNumber();
            List<BlockInfo> levelBlocks = getBlockInfoForLevel(blockNumber);
            if (levelBlocks == null) {
                levelBlocks = new ArrayList<>();
            }

            // correct block info
            // assuming side chain, with warnings upon encountered issues
            BlockInfo blockInfo = new BlockInfo(block.getHash(), block.getDifficultyBI().add(parentTotalDifficulty), false);

            // looking through the other block info on that level
            List<BlockInfo> mainChain = new ArrayList<>();
            for (BlockInfo bi : levelBlocks) {
                if (bi.isMainChain()) {
                    mainChain.add(bi);
                }
            }

            // ensuring that there exists only one main chain at present
            if (mainChain.size() > 1) {
                LOG.error(
                        "The database is corrupted. There are two different main chain blocks at level {}."
                                + " Please shutdown the kernel and rollback the block information by executing:\t./aion.sh -r {} -n <network>",
                        blockNumber, blockNumber - 1);
            }

            levelBlocks.add(blockInfo);
            setBlockInfoForLevel(blockNumber, levelBlocks);

            return blockInfo.getCummDifficulty();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public String dumpPastBlocks(long numberOfBlocks, String reportsFolder) throws IOException {
        lock.readLock().lock();

        try {
            long firstBlock = getMaxNumber();
            if (firstBlock < 0) {
                return null;
            }
            long lastBlock = firstBlock - numberOfBlocks;

            File file = new File(reportsFolder, System.currentTimeMillis() + "-blocks-report.out");

            BufferedWriter writer = new BufferedWriter(new FileWriter(file));

            while (firstBlock > lastBlock && firstBlock >= 0) {
                List<BlockInfo> levelBlocks = getBlockInfoForLevel(firstBlock);

                writer.append("Blocks at level " + firstBlock + ":");
                writer.newLine();

                for (BlockInfo bi : levelBlocks) {
                    writer.append(
                            "\nBlock hash from index database: "
                                    + Hex.toHexString(bi.getHash())
                                    + "\nTotal Difficulty: "
                                    + bi.getCummDifficulty()
                                    + "\nBlock on main chain: "
                                    + String.valueOf(bi.isMainChain()).toUpperCase());
                    writer.newLine();
                    AionBlock blk = getBlockByHash(bi.getHash());
                    if (blk != null) {
                        writer.append("\nFull block data:\n");
                        writer.append(blk.toString());
                        writer.newLine();
                    } else {
                        writer.append("Retrieved block data is null.");
                    }
                }
                writer.newLine();

                firstBlock--;
            }

            writer.close();
            return file.getName();
        } finally {
            lock.readLock().unlock();
        }
    }

    String dumpPastBlocksForConsensusTest(long firstBlock, String reportsFolder)
            throws IOException {
        lock.readLock().lock();

        try {
            if (firstBlock < 0) {
                return null;
            }

            // the 1st block will be imported by the test
            // its total difficulty, state root and receipt hash can be used for validation
            // the 2nd block will be used to setup the blockchain world state before import
            // the 3rd block is also part of the setup as it is required for header validation
            long lastBlock = firstBlock - 3;

            File file =
                    new File(
                            reportsFolder,
                            System.currentTimeMillis() + "-blocks-for-consensus-test.out");

            BufferedWriter writer = new BufferedWriter(new FileWriter(file));

            while (firstBlock > lastBlock && firstBlock >= 0) {
                List<BlockInfo> levelBlocks = getBlockInfoForLevel(firstBlock);

                for (BlockInfo bi : levelBlocks) {
                    if (bi.mainChain) {
                        writer.append(
                                "\nBlock hash from index database: "
                                        + Hex.toHexString(bi.getHash())
                                        + "\nTotal Difficulty: "
                                        + bi.getCummDifficulty()
                                        + "\nBlock on main chain: "
                                        + String.valueOf(bi.isMainChain()).toUpperCase());
                        writer.newLine();
                        AionBlock blk = getBlockByHash(bi.getHash());
                        if (blk != null) {
                            writer.append("\nFull block data:\n");
                            writer.append(blk.toString());
                            writer.newLine();
                        } else {
                            writer.append("Retrieved block data is null.");
                        }
                    }
                }
                writer.newLine();

                firstBlock--;
            }

            writer.close();
            return file.getName();
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<byte[]> getListHashesStartWith(long number, long maxBlocks) {
        lock.readLock().lock();

        try {
            List<byte[]> result = new ArrayList<>();

            int i;
            for (i = 0; i < maxBlocks; ++i) {
                List<BlockInfo> blockInfos = index.get(number);
                if (blockInfos == null) {
                    break;
                }

                for (BlockInfo blockInfo : blockInfos) {
                    if (blockInfo.isMainChain()) {
                        result.add(blockInfo.getHash());
                        break;
                    }
                }

                ++number;
            }
            maxBlocks -= i;

            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean isIndexed(byte[] hash, long level) {
        lock.readLock().lock();

        try {
            // when null -> there was no block info for the hash
            return getBlockInfoForHash(getBlockInfoForLevel(level), hash) != null;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * First checks if the size key is missing or smaller than it should be. If it is incorrect, the
     * method attempts to correct it by setting it to the given level.
     */
    public void correctSize(long maxNumber, Logger log) {
        // correcting the size if smaller than should be
        long storedSize = index.getStoredSize();
        if (maxNumber >= storedSize) {
            // can't change size directly, so we do a put + delete the next level to reset it
            index.set(maxNumber + 1, new ArrayList<>());
            index.remove(maxNumber + 1);
            log.info(
                    "Corrupted index size corrected from {} to {}.",
                    storedSize,
                    index.getStoredSize());
        }
    }

    /** Sets the block as main chain and all its ancestors. Used by the data recovery methods. */
    public void correctMainChain(AionBlock block, Logger log) {
        lock.writeLock().lock();

        try {
            AionBlock currentBlock = block;
            if (currentBlock != null) {
                List<BlockInfo> infos = getBlockInfoForLevel(currentBlock.getNumber());
                BlockInfo thisBlockInfo = getBlockInfoForHash(infos, currentBlock.getHash());

                // loop stops when the block is null or is already main chain
                while (thisBlockInfo != null && !thisBlockInfo.isMainChain()) {
                    log.info(
                            "Setting block hash: {}, number: {} to main chain.",
                            currentBlock.getShortHash(),
                            currentBlock.getNumber());

                    // fix the info for the current block
                    infos.remove(thisBlockInfo);
                    thisBlockInfo.setMainChain(true);
                    infos.add(thisBlockInfo);
                    setBlockInfoForLevel(currentBlock.getNumber(), infos);

                    // fix the info for parent
                    currentBlock = getBlockByHash(currentBlock.getParentHash());
                    if (currentBlock != null) {
                        infos = getBlockInfoForLevel(currentBlock.getNumber());
                        thisBlockInfo = getBlockInfoForHash(infos, currentBlock.getHash());
                    } else {
                        thisBlockInfo = null;
                    }
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public static class BlockInfo implements Serializable {

        /**
         * Constructor of the BlockInfo instead of the default constructor, requires 3 arguments input.
         *
         * @param hash block hash
         * @param cummDifficulty the cummulateDifficulty of this block
         * @param mainChain is belong to mainchain block
         */
        public BlockInfo(byte[] hash, BigInteger cummDifficulty, boolean mainChain) {
            if (hash == null || cummDifficulty == null || cummDifficulty.signum() == -1) {
                throw new IllegalArgumentException();
            }

            this.hash = hash;
            this.cummDifficulty = cummDifficulty;
            this.mainChain = mainChain;
        }

        public BlockInfo(byte[] ser) {
            RLPList outerList = RLP.decode2(ser);

            if (outerList.isEmpty()) {
                throw new IllegalArgumentException("Rlp decode error during construct the BlockInfo.");
            }

            RLPList list = (RLPList) outerList.get(0);
            this.hash = list.get(0).getRLPData();
            this.cummDifficulty = ByteUtil.bytesToBigInteger(list.get(1).getRLPData());

            byte[] boolData = list.get(2).getRLPData();
            this.mainChain =
                    !(boolData == null || boolData.length == 0) && boolData[0] == (byte) 0x1;
        }

        private static final long serialVersionUID = 7279277944605144671L;

        private byte[] hash;

        private BigInteger cummDifficulty;

        private boolean mainChain;

        public byte[] getHash() {
            return hash;
        }

        public BigInteger getCummDifficulty() {
            return cummDifficulty;
        }

        @VisibleForTesting
        public void setCummDifficulty(BigInteger diff) {
            cummDifficulty = diff;
        }

        public void setMainChain(boolean mainChain) {
            this.mainChain = mainChain;
        }

        boolean isMainChain() {
            return mainChain;
        }

        public byte[] getEncoded() {
            byte[] hashElement = RLP.encodeElement(hash);
            byte[] cumulativeDiffElement = RLP.encodeElement(cummDifficulty.toByteArray());
            byte[] mainChainElement = RLP.encodeByte(mainChain ? (byte) 0x1 : (byte) 0x0);
            return RLP.encodeList(hashElement, cumulativeDiffElement, mainChainElement);
        }
    }

    private static class MigrationRedirectingInputStream extends ObjectInputStream {

        MigrationRedirectingInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (desc.getName().equals("org.aion.db.a0.AionBlockStore$BlockInfo")) {
                return BlockInfo.class;
            }
            return super.resolveClass(desc);
        }
    }

    /**
     * Called by {@link AionBlockStore#BLOCK_INFO_SERIALIZER} for now, on main-net launch we should
     * default to this class.
     */
    private static final Serializer<List<BlockInfo>, byte[]> BLOCK_INFO_RLP_SERIALIZER =
            new Serializer<>() {
                @Override
                public byte[] serialize(List<BlockInfo> object) {
                    byte[][] infoList = new byte[object.size()][];
                    int i = 0;
                    for (BlockInfo b : object) {
                        infoList[i] = b.getEncoded();
                        i++;
                    }
                    return RLP.encodeList(infoList);
                }

                @Override
                public List<BlockInfo> deserialize(byte[] stream) {
                    RLPList list = (RLPList) RLP.decode2(stream).get(0);
                    List<BlockInfo> res = new ArrayList<>(list.size());

                    for (RLPElement aList : list) {
                        res.add(new BlockInfo(aList.getRLPData()));
                    }
                    return res;
                }
            };

    public static final Serializer<List<BlockInfo>, byte[]> BLOCK_INFO_SERIALIZER =
            new Serializer<>() {

                @Override
                public byte[] serialize(List<BlockInfo> value) {
                    return BLOCK_INFO_RLP_SERIALIZER.serialize(value);
                }

                @SuppressWarnings("unchecked")
                @Override
                public List<BlockInfo> deserialize(byte[] bytes) {
                    try {
                        return BLOCK_INFO_RLP_SERIALIZER.deserialize(bytes);
                    } catch (Exception e) {
                        // fallback logic for old block infos
                        try {
                            ByteArrayInputStream bis =
                                    new ByteArrayInputStream(bytes, 0, bytes.length);
                            ObjectInputStream ois = new MigrationRedirectingInputStream(bis);
                            return (List<BlockInfo>) ois.readObject();
                        } catch (IOException | ClassNotFoundException e2) {
                            throw new RuntimeException(e2);
                        }
                    }
                }
            };

    public void printChain() {
        lock.readLock().lock();

        try {
            long number = getMaxNumber();

            for (int i = 0; i < number; ++i) {
                List<BlockInfo> levelInfos = index.get(i);

                if (levelInfos != null) {
                    System.out.print(i);
                    for (BlockInfo blockInfo : levelInfos) {
                        if (blockInfo.isMainChain()) {
                            System.out.print(" [" + shortHash(blockInfo.getHash()) + "] ");
                        } else {
                            System.out.print(" " + shortHash(blockInfo.getHash()) + " ");
                        }
                    }
                    System.out.println();
                }
            }
        } finally {
            lock.readLock().unlock();
        }
    }

    /** @implNote The method calling this method must handle the locking. */
    private List<BlockInfo> getBlockInfoForLevel(long level) {
        // locks acquired by calling method
        return index.get(level);
    }

    /** @implNote The method calling this method must handle the locking. */
    private void setBlockInfoForLevel(long level, List<BlockInfo> infos) {
        // locks acquired by calling method
        index.set(level, infos);
    }

    /**
     * @return the hash information if it is present in the list or {@code null} when the given
     *     block list is {@code null} or the hash is not present in the list
     * @implNote The method calling this method must handle the locking.
     */
    private static BlockInfo getBlockInfoForHash(List<BlockInfo> blocks, byte[] hash) {
        if (blocks == null) {
            return null;
        }
        for (BlockInfo blockInfo : blocks) {
            if (Arrays.equals(hash, blockInfo.getHash())) {
                return blockInfo;
            }
        }
        return null;
    }

    @Override
    public void load() {
        if (checkIntegrity) {
            indexIntegrityCheck();
        }
    }

    public enum IntegrityCheckResult {
        MISSING_GENESIS,
        MISSING_LEVEL,
        FIXED,
        CORRECT
    }

    public IntegrityCheckResult indexIntegrityCheck() {
        if (index.size() > 0) {
            LOG_CONS.info("Checking the integrity of the total difficulty information...");

            // check each block's total difficulty till genesis
            boolean correct = true;
            AionBlock block = getBestBlock();
            long start, round, time;
            start = round = System.currentTimeMillis();
            long bestBlockNumber = block.getNumber();

            while (correct && block.getNumber() > 0) {
                // it is correct if there is no inconsistency wrt to the parent
                correct =
                        getTotalDifficultyForHash(block.getHash())
                                .equals(
                                        getTotalDifficultyForHash(block.getParentHash())
                                                .add(block.getDifficultyBI()));

                if (!correct) {
                    LOG_CONS.info(
                            "Total difficulty for block hash: {} number: {} is {}.",
                            block.getShortHash(),
                            block.getNumber(),
                            "NOT OK");
                } else {
                    time = System.currentTimeMillis();
                    if (time - round > 4999) {
                        long remaining = block.getNumber();
                        long checked = bestBlockNumber - block.getNumber() + 1;
                        double duration = (time - start) / 1000;
                        double approx = remaining * (duration / checked);
                        approx = approx >= 1 ? approx : 1;

                        LOG_CONS.info(
                                "{} blocks checked in {} sec. {} more blocks to verify. Approximate completion time is {} sec.",
                                checked,
                                (long) duration,
                                remaining,
                                (long) approx);
                        round = time;
                    }
                }

                // check parent next
                block = getBlockByHash(block.getParentHash());
            }

            // check correct TD for genesis block
            if (block.getNumber() == 0) {
                correct =
                        getTotalDifficultyForHash(block.getHash()).equals(block.getDifficultyBI());
                if (!correct) {
                    LOG_CONS.info(
                            "Total difficulty for block hash: {} number: {} is {}.",
                            block.getShortHash(),
                            block.getNumber(),
                            "NOT OK");
                } else {
                    time = ((System.currentTimeMillis() - start) / 1000) + 1;
                    LOG_CONS.info("{} blocks checked in under {} sec.", bestBlockNumber + 1, time);
                }
            }

            // if any inconsistency, correct the TD
            if (!correct) {
                LOG_CONS.info(
                        "Integrity check of total difficulty found INVALID information. Correcting ...");

                List<BlockInfo> infos = getBlockInfoForLevel(0);
                if (infos == null) {
                    LOG_CONS.error(
                            "Missing genesis block information. Cannot recover without deleting database.");
                    return IntegrityCheckResult.MISSING_GENESIS;
                }

                for (BlockInfo bi : infos) {
                    block = getBlockByHash(bi.getHash());
                    bi = new BlockInfo(block.getHash(), block.getDifficultyBI(), bi.isMainChain());
                    LOG_CONS.info(
                            "Correcting total difficulty for block hash: {} number: {} to {}.",
                            block.getShortHash(),
                            block.getNumber(),
                            bi.getCummDifficulty());
                }
                setBlockInfoForLevel(0, infos);

                long level = 1;

                do {
                    infos = getBlockInfoForLevel(level);
                    if (infos == null) {
                        LOG_CONS.error(
                                "Missing block information at level {}."
                                        + " Cannot recover without reverting to block number {}.",
                                level,
                                (level - 1));
                        return IntegrityCheckResult.MISSING_LEVEL;
                    }

                    for (BlockInfo bi : infos) {
                        block = getBlockByHash(bi.getHash());
                        bi = new BlockInfo(block.getHash(), block.getDifficultyBI()
                            .add(getTotalDifficultyForHash(block.getParentHash())), bi.isMainChain());
                        LOG_CONS.info(
                                "Correcting total difficulty for block hash: {} number: {} to {}.",
                                block.getShortHash(),
                                block.getNumber(),
                                bi.getCummDifficulty());
                    }
                    setBlockInfoForLevel(level, infos);

                    level++;
                } while (level < index.size());

                LOG_CONS.info("Total difficulty correction COMPLETE.");
                return IntegrityCheckResult.FIXED;
            } else {
                return IntegrityCheckResult.CORRECT;
            }
        } else {
            return IntegrityCheckResult.CORRECT;
        }
    }

    @Override
    public void close() {
        lock.writeLock().lock();

        try {
            index.close();
        } catch (Exception e) {
            LOG.error("Not able to close the index database:", e);
        } finally {
            try {
                blocks.close();
            } catch (Exception e) {
                LOG.error("Not able to close the blocks database:", e);
            } finally {
                lock.writeLock().unlock();
            }
        }
    }

    @Override
    public void rollback(long blockNumber) {
        lock.writeLock().lock();

        try {

            long level = index.size() - 1;

            LOG.debug("blockstore rollback block level from {} to {}", level, blockNumber);

            while (level > blockNumber) {
                // remove all the blocks at that level
                List<BlockInfo> currentLevelBlocks = getBlockInfoForLevel(level);

                for (BlockInfo bk_info : currentLevelBlocks) {
                    blocks.delete(bk_info.getHash());
                }

                index.remove(level--);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
}
