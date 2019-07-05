package org.aion.zero.impl;

import java.math.BigInteger;
import java.util.Map;
import org.aion.mcf.db.InternalVmType;
import org.aion.mcf.db.RepositoryCache;
import org.aion.mcf.vm.types.DataWordImpl;
import org.aion.precompiled.ContractFactory;
import org.aion.types.AionAddress;
import org.aion.util.types.ByteArrayWrapper;
import org.aion.zero.impl.db.AionRepositoryImpl;

/** {@link AionHub} functionality where a full instantiation of the class is not desirable. */
public class AionHubUtils {

    public static void buildGenesis(AionGenesis genesis, AionRepositoryImpl repository) {
        // initialization section for network balance contract
        RepositoryCache track = repository.startTracking();

        AionAddress networkBalanceAddress = ContractFactory.getTotalCurrencyContractAddress();
        track.createAccount(networkBalanceAddress);
        // saving FVM type for networkBalance contract
        track.saveVmType(networkBalanceAddress, InternalVmType.FVM);

        for (Map.Entry<Integer, BigInteger> addr : genesis.getNetworkBalances().entrySet()) {
            // assumes only additions are performed in the genesis
            track.addStorageRow(
                    networkBalanceAddress,
                    new DataWordImpl(addr.getKey()).toWrapper(),
                    wrapValueForPut(new DataWordImpl(addr.getValue())));
        }

        for (AionAddress addr : genesis.getPremine().keySet()) {
            track.createAccount(addr);
            track.addBalance(addr, genesis.getPremine().get(addr).getBalance());
        }
        track.flush();

        repository.commitBlock(genesis.getHeader());
        repository.getBlockStore().saveBlock(genesis, genesis.getDifficultyBI(), true);
    }

    private static ByteArrayWrapper wrapValueForPut(DataWordImpl value) {
        return (value.isZero())
                ? value.toWrapper()
                : new ByteArrayWrapper(value.getNoLeadZeroesData());
    }
}
