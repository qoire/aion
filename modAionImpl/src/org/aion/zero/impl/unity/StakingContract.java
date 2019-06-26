package org.aion.zero.impl.unity;

import avm.Address;
import avm.Blockchain;
import avm.Result;
import org.aion.avm.userlib.AionMap;

import java.math.BigInteger;
import java.util.Map;

public class StakingContract {
    
    static {
        stakers = new AionMap();
    }
    
    private static class Staker {
        private BigInteger totalVote;
        
        // maps addresses to the votes those addresses have sent to this staker
        // the sum of votes.values() should always equal totalVote
        private Map<Address, BigInteger> votes;
    }
    
    private static Map<Address, Staker> stakers;
    
    public static byte[] main() {
        return null;
    }

    public static boolean register(Address address) {
        if (Blockchain.getAddress().equals(address)) {
            stakers.put(address, new Staker());
            return true;
        } else {
            return false;
        }
    }

    public static boolean vote(Address stakerAddress) {
        BigInteger value = Blockchain.getValue();
        Address senderAddress = Blockchain.getAddress();
        if (null != stakerAddress && stakers.containsKey(stakerAddress) && value.compareTo(BigInteger.ZERO) > 0) {
            Staker staker = stakers.get(stakerAddress);
            staker.totalVote = staker.totalVote.add(value);
            
            BigInteger vote = staker.votes.get(senderAddress);
            if (null == vote) {
                // This is the first time the sender has voted for this staker
                staker.votes.put(senderAddress, value);
            } else {
                staker.votes.replace(senderAddress, vote.add(value));
            }
            return true;
        } else {
            return false;
        }
    }

    public static boolean unvote(Address stakerAddress, long amount) {
        Address senderAddress = Blockchain.getAddress();
        BigInteger amountBI = BigInteger.valueOf(amount);
        boolean success = false;
        if (null != stakerAddress && stakers.containsKey(stakerAddress)) {
            Staker staker = stakers.get(stakerAddress);
            if (staker.votes.containsKey(senderAddress)) {
                BigInteger vote = staker.votes.get(senderAddress);
                if (vote.compareTo(amountBI) >= 0) {
                    Result result = Blockchain.call(senderAddress, amountBI, new byte[0], Blockchain.getRemainingEnergy());
                    if (result.isSuccess()) {
                        if (vote.compareTo(amountBI) > 0) {
                            staker.votes.replace(senderAddress, vote.subtract(amountBI));
                        } else {
                            staker.votes.remove(senderAddress);
                        }
                        staker.totalVote = staker.totalVote.subtract(amountBI);
                        success = true;
                    }
                }
            }
        }
        return success;
    }
}