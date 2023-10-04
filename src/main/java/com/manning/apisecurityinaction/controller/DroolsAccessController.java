package com.manning.apisecurityinaction.controller;

import java.util.HashMap;
import java.util.Map;

import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;

public class DroolsAccessController extends ABACAccessController {
    private final KieContainer kieContainer;

    public DroolsAccessController() {
        this.kieContainer = KieServices.get().getKieClasspathContainer();
    }

    @Override
    Decision checkPermitted(Map<String, Object> subAttrs, Map<String, Object> resourceAttrs,
            Map<String, Object> actionAttrs, Map<String, Object> envAttrs) {
        var session = kieContainer.newKieSession();
        try {
            var decision = new Decision();
            session.setGlobal("decision", decision);
            session.insert(new Subject(subAttrs));
            session.insert(new Resource(resourceAttrs));
            session.insert(new Action(actionAttrs));
            session.insert(new Environment(envAttrs));

            session.fireAllRules();

            return decision;
        } finally {
            session.dispose();
        }
    }

    public static class Subject extends HashMap<String, Object> {
        public Subject(Map<String, Object> m) {
            super(m);
        }
    }

    public static class Resource extends HashMap<String, Object> {
        public Resource(Map<String, Object> m) {
            super(m);
        }
    }

    public static class Action extends HashMap<String, Object> {
        public Action(Map<String, Object> m) {
            super(m);
        }
    }

    public static class Environment extends HashMap<String, Object> {
        public Environment(Map<String, Object> m) {
            super(m);
        }
    }
}
