package org.zaproxy.addon.securityproxy.proxytests;

import java.util.Objects;

public class CreHostCombi {
    private String host;
    private String username;

    public CreHostCombi(String host, String username) {
        this.host = host;
        this.username = username;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CreHostCombi that = (CreHostCombi) o;
        return Objects.equals(host, that.host) && Objects.equals(username, that.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(host, username);
    }

    @Override
    public String toString() {
        return "CreHostCombi{" +
                "host='" + host + '\'' +
                ", username='" + username + '\'' +
                '}';
    }
}
