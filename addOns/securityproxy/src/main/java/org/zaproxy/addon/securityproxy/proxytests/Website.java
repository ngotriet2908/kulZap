package org.zaproxy.addon.securityproxy.proxytests;

import java.io.Serializable;

public class Website implements Serializable {
    private String host;
    private Website directedWebsite;

    static final long serialVersionUID = 42L;

    public Website(String host) {
        this.host = host;
    }

    public Website(String host, Website directedWebsite) {
        this.host = host;
        this.directedWebsite = directedWebsite;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public Website getDirectedWebsite() {
        return directedWebsite;
    }

    public void setDirectedWebsite(Website directedWebsite) {
        this.directedWebsite = directedWebsite;
    }

    @Override
    public String toString() {
        return "Website{" +
                "host='" + host + '\'' +
                ", directedWebsite=" + directedWebsite +
                '}';
    }
}
