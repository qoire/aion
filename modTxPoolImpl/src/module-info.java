module aion.txpool.impl {
    requires aion.log;
    requires slf4j.api;
    requires aion.util;
    requires aion.txpool;
    requires aion.types;
    requires aion.base;

    provides org.aion.txpool.ITxPool with
            org.aion.txpool.zero.TxPoolA0;

    exports org.aion.txpool.zero;
}
