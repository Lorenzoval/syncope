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
package org.apache.syncope.common.keymaster.rest.api.service;

import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.Serializable;
import java.util.List;
import org.apache.syncope.common.keymaster.client.api.model.Domain;
import org.apache.syncope.common.lib.types.CipherAlgorithm;

/**
 * REST operations for Self Keymaster's domains.
 */
@Path("domains")
public interface DomainService extends Serializable {

    @GET
    @Produces({ MediaType.APPLICATION_JSON })
    List<Domain> list();

    @GET
    @Path("{key}")
    @Produces({ MediaType.APPLICATION_JSON })
    Domain read(@NotNull @PathParam("key") String key);

    @POST
    @Consumes({ MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_JSON })
    Response create(Domain domain);

    @POST
    @Path("{key}/changeAdminPassword")
    @Produces({ MediaType.APPLICATION_JSON })
    Response changeAdminPassword(
            @NotNull @PathParam("key") String key,
            @QueryParam("password") String password,
            @QueryParam("cipherAlgorithm") CipherAlgorithm cipherAlgorithm);

    @POST
    @Path("{key}/adjustPoolSize")
    @Produces({ MediaType.APPLICATION_JSON })
    Response adjustPoolSize(
            @NotNull @PathParam("key") String key,
            @QueryParam("poolMaxActive") int poolMaxActive,
            @QueryParam("poolMinIdle") int poolMinIdle);

    @DELETE
    @Path("{key}")
    @Produces({ MediaType.APPLICATION_JSON })
    Response delete(@NotNull @PathParam("key") String key);
}
