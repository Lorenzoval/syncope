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
package org.apache.syncope.client.cli.commands.task;

import javax.xml.ws.WebServiceException;
import org.apache.syncope.client.cli.Input;
import org.apache.syncope.common.lib.SyncopeClientException;

public class TaskDelete extends AbstractTaskCommand {

    private static final String DELETE_HELP_MESSAGE = "task --delete {TASK-ID} {TASK-ID} [...]";

    private final Input input;

    public TaskDelete(final Input input) {
        this.input = input;
    }

    public void delete() {

        if (input.parameterNumber() >= 1) {
            for (final String parameter : input.getParameters()) {
                try {
                    taskService.delete(Long.valueOf(parameter));
                    taskResultManager.deletedMessage("Task", parameter);
                } catch (final WebServiceException | SyncopeClientException ex) {
                    if (ex.getMessage().startsWith("NotFound")) {
                        taskResultManager.notFoundError("Task", parameter);
                    } else if (ex.getMessage().startsWith("DataIntegrityViolation")) {
                        taskResultManager.generic("You cannot delete task " + parameter);
                    } else {
                        taskResultManager.generic(ex.getMessage());
                    }
                } catch (final NumberFormatException ex) {
                    taskResultManager.notBooleanDeletedError("task", parameter);
                }
            }
        } else {
            taskResultManager.commandOptionError(DELETE_HELP_MESSAGE);
        }
    }
}
