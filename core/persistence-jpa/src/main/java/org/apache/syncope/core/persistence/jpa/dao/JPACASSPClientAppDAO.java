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
package org.apache.syncope.core.persistence.jpa.dao;

import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import java.util.List;
import org.apache.syncope.core.persistence.api.dao.CASSPClientAppDAO;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.am.CASSPClientApp;
import org.apache.syncope.core.persistence.api.entity.policy.Policy;
import org.apache.syncope.core.persistence.jpa.entity.am.JPACASSPClientApp;
import org.springframework.transaction.annotation.Transactional;

public class JPACASSPClientAppDAO extends AbstractClientAppDAO<CASSPClientApp> implements CASSPClientAppDAO {

    @Override
    public CASSPClientApp find(final String key) {
        return entityManager().find(JPACASSPClientApp.class, key);
    }

    private CASSPClientApp find(final String column, final Object value) {
        TypedQuery<CASSPClientApp> query = entityManager().createQuery(
                "SELECT e FROM " + JPACASSPClientApp.class.getSimpleName() + " e WHERE e." + column + "=:value",
                CASSPClientApp.class);
        query.setParameter("value", value);

        CASSPClientApp result = null;
        try {
            result = query.getSingleResult();
        } catch (final NoResultException e) {
            LOG.debug("No OIDCRP found with " + column + " {}", value, e);
        }

        return result;
    }

    @Override
    public CASSPClientApp findByClientAppId(final Long clientAppId) {
        return find("clientAppId", clientAppId);
    }

    @Override
    public CASSPClientApp findByName(final String name) {
        return find("name", name);
    }

    @Override
    public List<CASSPClientApp> findByPolicy(final Policy policy) {
        return findByPolicy(policy, CASSPClientApp.class, JPACASSPClientApp.class);
    }

    @Override
    public List<CASSPClientApp> findByRealm(final Realm realm) {
        return findByRealm(realm, CASSPClientApp.class, JPACASSPClientApp.class);
    }

    @Transactional(readOnly = true)
    @Override
    public List<CASSPClientApp> findAll() {
        TypedQuery<CASSPClientApp> query = entityManager().createQuery(
                "SELECT e FROM " + JPACASSPClientApp.class.getSimpleName() + " e", CASSPClientApp.class);

        return query.getResultList();
    }

    @Override
    public CASSPClientApp save(final CASSPClientApp clientApp) {
        return entityManager().merge(clientApp);
    }

    @Override
    public void delete(final String key) {
        CASSPClientApp rpTO = find(key);
        if (rpTO == null) {
            return;
        }

        delete(rpTO);
    }

    @Override
    public void delete(final CASSPClientApp clientApp) {
        entityManager().remove(clientApp);
    }
}
