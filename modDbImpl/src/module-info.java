module aion.db.impl {
    requires slf4j.api;
    requires aion.log;
    requires aion.util;
    requires rocksdbjni;
    requires h2.mvstore;
    requires com.google.common;
    requires mongo.java.driver;
    requires leveldbjni.all;

    exports org.aion.db.impl;
    exports org.aion.db.impl.leveldb;
    exports org.aion.db.impl.rocksdb;
}
