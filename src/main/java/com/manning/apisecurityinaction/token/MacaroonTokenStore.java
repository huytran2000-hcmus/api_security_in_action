package com.manning.apisecurityinaction.token;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import com.github.nitram509.jmacaroons.verifier.TimestampCaveatVerifier;

import spark.Request;

public class MacaroonTokenStore implements SecureTokenStore {
    private final TokenStore delegate;
    private final Key macKey;

    public static SecureTokenStore wrap(ConfidentialTokenStore store, Key macKey) {
        return new MacaroonTokenStore(store, macKey);
    }

    public static AuthenticatedTokenStore wrap(TokenStore store, Key macKey) {
        return new MacaroonTokenStore(store, macKey);
    }

    private MacaroonTokenStore(TokenStore delegate, Key macKey) {
        this.delegate = delegate;
        this.macKey = macKey;
    }

    @Override
    public String create(Request request, Token token) {
        var identifier = delegate.create(request, token);
        var macaroon = MacaroonsBuilder.create("", macKey.getEncoded(), identifier);

        return macaroon.serialize();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var macaroon = MacaroonsBuilder.deserialize(tokenId);

        var verifier = new MacaroonsVerifier(macaroon);
        verifier.satisfyGeneral(new TimestampCaveatVerifier());
        verifier.satisfyExact("method: " + request.requestMethod());
        verifier.satisfyGeneral(new SinceVerifier(request));

        if (!verifier.isValid(macKey.getEncoded())) {
            return Optional.empty();
        }

        return delegate.read(request, macaroon.identifier);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var macaroon = MacaroonsBuilder.deserialize(tokenId);
        var verifier = new MacaroonsVerifier(macaroon);
        if (!verifier.isValid(macKey.getEncoded())) {
            return;
        }

        delegate.revoke(request, macaroon.identifier);
    }

    private static class SinceVerifier implements GeneralCaveatVerifier {
        private final Request request;

        private SinceVerifier(Request request) {
            this.request = request;
        }

        @Override
        public boolean verifyCaveat(String caveat) {
            if (!caveat.startsWith("since > ", 0)) {
                return false;
            }

            var minSince = Instant.parse(caveat.substring(8));
            var reqSince = Instant.now().minus(1, ChronoUnit.DAYS);

            var sinceParam = request.queryParams("since");
            if (sinceParam != null) {
                reqSince = Instant.parse(sinceParam);
            }

            return reqSince.isAfter(minSince);
        }

    }
}
