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
package org.apache.syncope.core.persistence.jpa.entity.user;

import com.fasterxml.jackson.core.type.TypeReference;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostUpdate;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import java.util.List;
import org.apache.syncope.core.persistence.api.entity.JSONLAPlainAttr;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.persistence.jpa.entity.JPAJSONEntityListener;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;

public class JPAJSONLinkedAccountListener extends JPAJSONEntityListener<User> {

    protected static final TypeReference<List<JPAJSONLAPlainAttr>> TYPEREF =
            new TypeReference<List<JPAJSONLAPlainAttr>>() {
    };

    @Override
    protected List<? extends JSONLAPlainAttr> getAttrs(final String plainAttrsJSON) {
        return POJOHelper.deserialize(plainAttrsJSON, TYPEREF);
    }

    @PostLoad
    public void read(final JPAJSONLinkedAccount account) {
        super.json2list(account, false);
    }

    @PrePersist
    @PreUpdate
    public void save(final JPAJSONLinkedAccount account) {
        super.list2json(account);
    }

    @PostPersist
    @PostUpdate
    public void readAfterSave(final JPAJSONLinkedAccount account) {
        super.json2list(account, true);
    }
}
