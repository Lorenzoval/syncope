/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.client.console.commons;

import java.util.ArrayList;
import java.util.List;
import org.apache.syncope.client.console.policies.PropagationPolicyDirectoryPanel;
import org.apache.syncope.client.console.policies.PullPolicyDirectoryPanel;
import org.apache.syncope.client.console.policies.PushPolicyDirectoryPanel;
import org.apache.wicket.PageReference;
import org.apache.wicket.extensions.markup.html.tabs.AbstractTab;
import org.apache.wicket.extensions.markup.html.tabs.ITab;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.ResourceModel;

public class IdMPolicyTabProvider implements PolicyTabProvider {

    private static final long serialVersionUID = 2822554006571803418L;

    @Override
    public List<ITab> buildTabList(final PageReference pageRef) {
        List<ITab> tabs = new ArrayList<>();

        tabs.add(new AbstractTab(new ResourceModel("policy.propagation")) {

            private static final long serialVersionUID = -6815067322125799251L;

            @Override
            public Panel getPanel(final String panelId) {
                return new PropagationPolicyDirectoryPanel(panelId, pageRef);
            }
        });

        tabs.add(new AbstractTab(new ResourceModel("policy.pull")) {

            private static final long serialVersionUID = -6815067322125799251L;

            @Override
            public Panel getPanel(final String panelId) {
                return new PullPolicyDirectoryPanel(panelId, pageRef);
            }
        });

        tabs.add(new AbstractTab(new ResourceModel("policy.push")) {

            private static final long serialVersionUID = -6815067322125799251L;

            @Override
            public Panel getPanel(final String panelId) {
                return new PushPolicyDirectoryPanel(panelId, pageRef);
            }
        });

        return tabs;
    }
}
