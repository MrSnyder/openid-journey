import dotenv from 'dotenv';
import * as client from 'openid-client';
import { Strategy } from 'openid-client/passport';
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import { ensureLoggedIn, ensureLoggedOut } from 'connect-ensure-login';

dotenv.config();

// Hotfix for currentUrl in Passport-Strateg
Strategy.prototype.currentUrl = (req) =>{
    // Use ${req.get('host')} instead of ${req.host}, so the port is included
    return new URL(`${req.protocol}://${req.get('host')}${req.originalUrl ?? req.url}`);
}

const openIdConfig = URL.parse(process.env.OPENID_CONFIG_URL);
const openIdClientId = process.env.OPENID_CLIENT_ID;
const sessionSecret = process.env.SESSION_SECRET;

const openIdScope = 'openid profile email'
const redirect_uri = 'http://localhost:3000/auth/callback';

const app = express();

async function main() {

    // Setup openid-client & passport
    const config = await client.discovery(openIdConfig, openIdClientId, null, null, {
        execute : [client.allowInsecureRequests]
    });
    client.useJwtResponseMode(config);
    // Activate signature validation of the id token (not considered strictly necessary)
    //client.enableNonRepudiationChecks(config);
    passport.use(new Strategy({
        config,
        scope: openIdScope,
        callbackURL: redirect_uri
    }, (tokens, verified) => {
        console.log(tokens);
        verified(null, tokens.claims())
    }));
    passport.serializeUser((user, cb) => {
        cb(null, user);
    });
    passport.deserializeUser((user, cb) => {
        return cb(null, user);
    });

    app.use(cookieParser());
    app.use(session({
        secret: sessionSecret,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 30 * 60 * 1000
        }
    }));
    app.use(passport.authenticate('session'));

    app.get('/', ensureLoggedIn('/auth/login'), (req, res) => {
        console.log(req.user);
        res.send(`Welcome ${req.user?.email || req.user?.sub}`);
    });
    app.get(
        '/auth/login',
        ensureLoggedOut('/auth/logout'),
        // successRedirect ???
        passport.authenticate(openIdConfig.host)
    );
    app.get(
        '/auth/callback',
        ensureLoggedOut('/auth/logout'),
        passport.authenticate(openIdConfig.host, { successRedirect: '/' })
    );
    app.get('/auth/logout', (req, res) => {
        req.logout(() => {
            res.redirect(
                client.buildEndSessionUrl(config, {
                    post_logout_redirect_uri: `${req.protocol}://${(req.get('host'))}`,
                }).href,
            )
        })
    });

    app.listen(3000, () => {
        console.log('Server running on http://localhost:3000');
    });
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
