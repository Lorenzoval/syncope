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

import jakarta.persistence.TypedQuery;
import java.util.List;
import org.apache.syncope.core.persistence.api.dao.SAML2SPEntityDAO;
import org.apache.syncope.core.persistence.api.entity.am.SAML2SPEntity;
import org.apache.syncope.core.persistence.jpa.entity.am.JPASAML2SPEntity;
import org.springframework.transaction.annotation.Transactional;

public class JPASAML2SPEntityDAO extends AbstractDAO<SAML2SPEntity> implements SAML2SPEntityDAO {

    @Override
    public List<SAML2SPEntity> findAll() {
        TypedQuery<SAML2SPEntity> query = entityManager().createQuery(
                "SELECT e FROM " + JPASAML2SPEntity.class.getSimpleName() + " e", SAML2SPEntity.class);
        return query.getResultList();
    }

    @Transactional(readOnly = true)
    @Override
    public SAML2SPEntity find(final String key) {
        return entityManager().find(JPASAML2SPEntity.class, key);
    }

    @Override
    public SAML2SPEntity save(final SAML2SPEntity entity) {
        return entityManager().merge(entity);
    }

    @Override
    public void delete(final SAML2SPEntity entity) {
        entityManager().remove(entity);
    }
}
