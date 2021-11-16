/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.securityproxy;

import java.awt.CardLayout;
import java.awt.Font;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;
import javax.swing.ImageIcon;
import javax.swing.JTextPane;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SessionListener;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.securityproxy.proxytests.Website;
import org.zaproxy.zap.extension.brk.impl.http.ProxyListenerBreak;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An Zap extension that implement typosquatting prevention.
 */
public class ExtensionSecurityProxy extends ExtensionAdaptor implements SessionChangedListener {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionSecurityProxy";

    protected static final String PREFIX = "securityProxy";

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final ImageIcon ICON =
            new ImageIcon(ExtensionSecurityProxy.class.getResource(RESOURCES + "/cake.png"));

    private static final String WEBSITE_FILE = "example/website.tmp";
    public static final String HTML_TEMPLATE = "example/warning_page.html";
    public static final String REDIRECT_HTML = "example/redirectPage.html";

    private ZapMenuItem menuExample;
    private AbstractPanel statusPanel;
    private SecurityProxyListener listener;

    private List<Website> websites;

    private static final Logger LOGGER = LogManager.getLogger(ExtensionSecurityProxy.class);

    public ExtensionSecurityProxy() {
        super(NAME);
        setI18nPrefix(PREFIX);
        listener = new SecurityProxyListener(this);
        websites = new ArrayList<>();

    }

    /**
     * initialize the extension meta-data when it is hooked to the ZAP application
     * in this case establish variables and create or load the WebsiteFile from storage
     * @param extensionHook extensionHook
     */
    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addProxyListener(this.listener);
        extensionHook.addSessionListener(this);
        websites = new ArrayList<>();

        createOrLoadWebsiteFile();
        // As long as we're not running as a daemon
        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }

    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
    }

    /**
     * @return extension status panel
     */
    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);
            JTextPane pane = new JTextPane();
            pane.setEditable(false);
            // Obtain (and set) a font with the size defined in the options
            pane.setFont(FontUtils.getFont("Dialog", Font.PLAIN));
            pane.setContentType("text/html");
            pane.setText(Constant.messages.getString(PREFIX + ".panel.msg"));
            statusPanel.add(pane);
        }
        return statusPanel;
    }

    /**
     * @return extension menu export functionality
     */
    private ZapMenuItem getMenuExample() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menuExample.addActionListener(
                    e -> {
                        // This is where you do what you want to do.
                        // In this case we'll just show a popup message.
                        exportToWebsiteFile();
                        View.getSingleton()
                                .showMessageDialog("Exported to url file");
                        // And display a file included with the add-on in the Output tab
                    });
        }
        return menuExample;
    }

    /**
     * The method create the WEBSITE_FILE if not exists
     * Load the stored Website objects from the storage
     */
    private void createOrLoadWebsiteFile() {

        LOGGER.log(Level.INFO, "Start CreateOrLoad url file");

        try {
            File f = new File(Constant.getZapHome(), WEBSITE_FILE);
            if (f.createNewFile()) {
                LOGGER.log(Level.INFO,"URL file not exists, create URL file");

            } else {
                LOGGER.log(Level.INFO,"URL exists, loading url file");
                try {
                    FileInputStream fis = new FileInputStream(f);
                    ObjectInputStream ois = new ObjectInputStream(fis);

                    Object obj = ois.readObject();
                    LOGGER.log(Level.INFO, obj);
                    ArrayList<?> ar = (ArrayList<?>) obj;
                    List<Website> websites = new ArrayList<>();
                    LOGGER.log(Level.INFO, "ar size: " + ar.size());

                    for (Object x : ar) {
                        websites.add((Website) x);
                    }

                    for(Website web: websites) {
                        LOGGER.log(Level.INFO, "Loading: " + web.toString());
                    }
                    LOGGER.log(Level.INFO, "Websites size: " + websites.size());

                    this.websites.addAll(websites);

                    ois.close();
                    fis.close();

                } catch(Exception e) {
                    LOGGER.error(e.getMessage());
                    this.websites = new ArrayList<>();
                }

            }

        } catch (Exception e) {
            this.listener.logToOutput(e.getMessage());
        }
    }

    /**
     * The method create the WEBSITE_FILE if not exists
     * Write the current Website objects from the storage
     */
    private void exportToWebsiteFile() {

        LOGGER.log(Level.INFO, "Start Exporting url file");

        try {
            File f = new File(Constant.getZapHome(), WEBSITE_FILE);
            if (f.createNewFile()) {
                LOGGER.log(Level.INFO,"URL file not exists, create URL file");

            } else {
                LOGGER.log(Level.INFO,"URL exists, loading url file");
                try {
                    FileOutputStream fos = new FileOutputStream(f);
                    ObjectOutputStream oos = new ObjectOutputStream(fos);

                    oos.writeObject(this.websites);
                    oos.close();
                    fos.close();

                    for(Website web: websites) {
                        LOGGER.log(Level.INFO, "Writing: " + web.toString());
                    }

                } catch(Exception e) {
                    LOGGER.error(e.getMessage());
                    this.websites = new ArrayList<>();
                }

            }

        } catch (Exception e) {
            this.listener.logToOutput(e.getMessage());
        }
    }

    public List<Website> getWebsites() {
        return websites;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    /**
     * When the application closes or user initiates another session
     * export the current websites list to storage
     * @param session
     */
    @Override
    public void sessionChanged(Session session) {
        exportToWebsiteFile();
    }

    @Override
    public void sessionAboutToChange(Session session) {
    }

    @Override
    public void sessionScopeChanged(Session session) {

    }

    @Override
    public void sessionModeChanged(Control.Mode mode) {

    }
}
