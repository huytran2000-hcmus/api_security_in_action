package com.manning.apisecurityinaction.controller;

import static spark.Spark.halt;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;

import spark.Request;
import spark.Response;

public abstract class ABACAccessController {
    public void enforcePolicy(Request request, Response response) {
        var subAttrs = new HashMap<String, Object>();
        subAttrs.put("user", request.attribute(UserController.USERNAME_ATTR_KEY));
        subAttrs.put("groups", request.attribute(UserController.GROUP_ATTR_KEY));

        var resourceAttrs = new HashMap<String, Object>();
        resourceAttrs.put("path", request.pathInfo());
        resourceAttrs.put("space", request.params(":spaceId"));

        var actionAttrs = new HashMap<String, Object>();
        actionAttrs.put("method", request.requestMethod());

        var envAttr = new HashMap<String, Object>();
        envAttr.put("timeOfDay", LocalTime.now());
        envAttr.put("ip", request.ip());

        var decision = checkPermitted(subAttrs, resourceAttrs, actionAttrs, envAttr);

        if (!decision.isPermitted()) {
            halt(403);
        }
    }

    abstract Decision checkPermitted(
            Map<String, Object> subAttrs,
            Map<String, Object> resourceAttrs,
            Map<String, Object> actionAttrs,
            Map<String, Object> envAttrs);

    public static class Decision {
        private boolean permit = true;

        public void deny() {
            permit = false;
        }

        public void permit() {
            permit = true;
        }

        public boolean isPermitted() {
            return permit;
        }
    }
}
