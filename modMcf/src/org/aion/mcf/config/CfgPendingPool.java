package org.aion.mcf.config;

import com.google.common.base.Objects;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

public class CfgPendingPool {

    private int txPendingTimeout;

    public CfgPendingPool() {
        this.txPendingTimeout = 86400;
    }

    public void fromXML(final XMLStreamReader sr) throws XMLStreamException {
        loop:
        while (sr.hasNext()) {
            int eventType = sr.next();
            switch (eventType) {
                case XMLStreamReader.START_ELEMENT:
                    String elementName = sr.getLocalName().toLowerCase();
                    switch (elementName) {
                        case "txpendingtimeout":
                            this.txPendingTimeout = Integer.parseInt(Cfg.readValue(sr));
                            if (this.txPendingTimeout < 60) { // 1 mins
                                this.txPendingTimeout = 60;
                            } else if (this.txPendingTimeout > 259200) { // 3 days
                                this.txPendingTimeout = 259200;
                            }
                            break;
                        default:
                            Cfg.skipElement(sr);
                            break;
                    }
                    break;
                case XMLStreamReader.END_ELEMENT:
                    break loop;
            }
        }
    }

    public String toXML() {
        final XMLOutputFactory output = XMLOutputFactory.newInstance();
        XMLStreamWriter xmlWriter;
        String xml;
        try {
            Writer strWriter = new StringWriter();
            xmlWriter = output.createXMLStreamWriter(strWriter);
            xmlWriter.writeCharacters("\r\n\t");
            xmlWriter.writeStartElement("tx");

            xmlWriter.writeCharacters("\r\n\t\t");
            xmlWriter.writeStartElement("txPendingTimeout");
            xmlWriter.writeCharacters(String.valueOf(this.getTxPendingTimeout()));
            xmlWriter.writeEndElement();

            xmlWriter.writeCharacters("\r\n\t");
            xmlWriter.writeEndElement();
            xml = strWriter.toString();
            strWriter.flush();
            strWriter.close();
            xmlWriter.flush();
            xmlWriter.close();
            return xml;
        } catch (IOException | XMLStreamException e) {
            e.printStackTrace();
            return "";
        }
    }

    public int getTxPendingTimeout() {
        return this.txPendingTimeout;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        org.aion.mcf.config.CfgPendingPool cfgPendingPool = (org.aion.mcf.config.CfgPendingPool) o;
        return txPendingTimeout == cfgPendingPool.txPendingTimeout;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(txPendingTimeout);
    }
}
