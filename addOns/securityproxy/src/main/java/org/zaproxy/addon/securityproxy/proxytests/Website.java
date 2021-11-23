package org.zaproxy.addon.securityproxy.proxytests;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Website class represents the visited website. Website is model to be compact for storing yet contains
 * enough information for process future requests.
 */
public class Website implements Serializable {
    private String host;
    private Website directedWebsite;
    private List<Credential> credentials;

    static final long serialVersionUID = 42L;

    /**
     * Create a known/legitimate website object
     * @param host the hostname from the request
     */
    public Website(String host) {
        this.host = host;
        this.credentials = new ArrayList<>();
    }

    /**
     * Create a typo website object with the legit website as directed page
     * @param host the typo hostname from the request
     * @param directedWebsite a legitimate website object that the typo derives from
     */
    public Website(String host, Website directedWebsite) {
        this.host = host;
        this.directedWebsite = directedWebsite;
        this.credentials = new ArrayList<>();
    }

    /**
     * @return hostname of the website
     */
    public String getHost() {
        return host;
    }

    /**
     * @return the website that should be directed too in case of typo website (null otherwise).
     */
    public Website getDirectedWebsite() {
        return directedWebsite;
    }

    public List<Credential> getCredentials() {
        return credentials;
    }

    @Override
    public String toString() {
        return "Website{" +
                "host='" + host + '\'' +
                ", directedWebsite=" + directedWebsite +
                ", credentials=" + credentials +
                '}';
    }
}
