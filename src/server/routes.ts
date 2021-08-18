import path from 'path'
import hbs from 'hbs'
import express, { Express } from 'express'
import bodyParser from 'body-parser';
import session from 'express-session';
import samlp from 'samlp'

import { IDP_PATHS } from '../constants';
import { getHashCode } from '../helpers';
import extend from 'extend';
import chalk from 'chalk';

const SessionParticipants = require('samlp/lib/sessionParticipants')

interface ConfigureRoutesOptions {
  app: Express,
  argv: any,
  hbsBlocks: any,
  idpOptions: any
}

export const configureRoutes = ({ app, argv, hbsBlocks, idpOptions } : ConfigureRoutesOptions) => {
  app.set('host', process.env.HOST || argv.host);
  app.set('port', process.env.PORT || argv.port);
  app.set('views', path.join(__dirname, '../../views'));

  app.set('view engine', 'hbs');
  app.set('view options', { layout: 'layout' })
  app.engine('handlebars', hbs.__express);
  
  hbs.registerHelper('extend', function(name, context) {
    var block = hbsBlocks[name];
    if (!block) {
      block = hbsBlocks[name] = [];
    }

    block.push(context.fn(this));
  });

  hbs.registerHelper('block', function(name) {
    const val = (hbsBlocks[name] || []).join('\n');
    // clear the block
    hbsBlocks[name] = [];
    return val;
  });


  hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
      new RegExp(' value=\"' + selected + '\"'), '$& selected="selected"');
  });

  hbs.registerHelper('getProperty', function(attribute, context) {
    return context[attribute];
  });

  hbs.registerHelper('serialize', function(context) {
    return new Buffer(JSON.stringify(context)).toString('base64');
  });

  app.use(bodyParser.urlencoded({extended: true}));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    secret: 'The universe works on a math equation that never even ever really ends in the end',
    resave: false,
    saveUninitialized: true,
    name: 'idp_sid',
    cookie: { maxAge: 60 * 60 * 1000 }
  }));

  const showUser = (request: any, response: any, next: express.NextFunction) => {
    response.render('user', {
      user: request.user,
      participant: request.participant,
      metadata: request.metadata,
      authnRequest: request.authnRequest,
      idp: request.idp.options,
      paths: IDP_PATHS
    });
  }

  /**
   * Shared Handlers
   */

  const parseSamlRequest = (request: any, response: any, next: express.NextFunction) => {
    samlp.parseRequest(request, function(err, data) {
      if (err) {
        return response.render('error', {
          message: 'SAML AuthnRequest Parse Error: ' + err.message,
          error: err
        });
      };
      if (data) {
        request.authnRequest = {
          relayState: request.query.RelayState || request.body.RelayState,
          id: data.id,
          issuer: data.issuer,
          destination: data.destination,
          acsUrl: data.assertionConsumerServiceURL,
          forceAuthn: data.forceAuthn === 'true'
        };
        console.log('Received AuthnRequest => \n', request.authnRequest);
      }
      return showUser(request, response, next);
    })
  };

  const getSessionIndex = (request: any) => {
    if (request && request.session) {
      return Math.abs(getHashCode(request.session.id)).toString();
    } else {
      return null;
    }
  }

  const getParticipant = (request: any) => {
    return {
      serviceProviderId: request.idp.options.serviceProviderId,
      sessionIndex: getSessionIndex(request),
      nameId: request.user.userName,
      nameIdFormat: request.user.nameIdFormat,
      serviceProviderLogoutURL: request.idp.options.sloUrl
    }
  }

  const parseLogoutRequest = function(request: any, response: any, next: express.NextFunction) {
    if (!request.idp.options.sloUrl) {
      return response.render('error', {
        message: 'SAML Single Logout Service URL not defined for Service Provider'
      });
    };

    return samlp.logout({
      issuer: request.idp.options.issuer,
      cert: request.idp.options.cert,
      key: request.idp.options.key,
      digestAlgorithm: request.idp.options.digestAlgorithm,
      signatureAlgorithm: request.idp.options.signatureAlgorithm,
      sessionParticipants: new SessionParticipants([request.participant]),
      clearIdPSession: (callback: any) => {
        console.log('Destroying session ' + request.session.id + ' for participant', request.participant);
        request.session.destroy();
        callback();
      }
    } as any)(request, response, next);
  }

  app.use((request, response, next) => {
    if (argv.rollSession) {
      request.session.regenerate((err) => {
        return next();
      });
    } else {
      next()
    }
  });

  app.use((request: any, response: any, next: express.NextFunction) => {
    request.user = argv.config.user;
    request.metadata = argv.config.metadata;
    request.idp = { options: idpOptions };
    request.participant = getParticipant(request);
    next();
  });

  app.get(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);
  app.post(['/', '/idp', IDP_PATHS.SSO], parseSamlRequest);

  app.get(IDP_PATHS.SLO, parseLogoutRequest);
  app.post(IDP_PATHS.SLO, parseLogoutRequest);

  app.post(IDP_PATHS.SIGN_IN, (request: any, response: any, next: express.NextFunction) => {
    const authOptions = extend({}, request.idp.options);
    Object.keys(request.body).forEach(function(key) {
      let buffer;
      if (key === '_authnRequest') {
        buffer = new Buffer(request.body[key], 'base64');
        request.authnRequest = JSON.parse(buffer.toString('utf8'));

        // Apply AuthnRequest Params
        authOptions.inResponseTo = request.authnRequest.id;
        if (request.idp.options.allowRequestAcsUrl && request.authnRequest.acsUrl) {
          authOptions.acsUrl = request.authnRequest.acsUrl;
          authOptions.recipient = request.authnRequest.acsUrl;
          authOptions.destination = request.authnRequest.acsUrl;
          authOptions.forceAuthn = request.authnRequest.forceAuthn;
        }
        if (request.authnRequest.relayState) {
          authOptions.RelayState = request.authnRequest.relayState;
        }
      } else {
        request.user[key] = request.body[key];
      }
    });

    if (!authOptions.encryptAssertion) {
      delete authOptions.encryptionCert;
      delete authOptions.encryptionPublicKey;
    }

    // Set Session Index
    authOptions.sessionIndex = getSessionIndex(request);

    // Keep calm and Single Sign On
    samlp.auth(authOptions)(request, response, next);
  })

  app.get(IDP_PATHS.METADATA, (request: any, response, next) => {
    samlp.metadata(request.idp.options)(request, response, next);
  });

  app.post(IDP_PATHS.METADATA, function(request: any, response, next) {
    if (request.body && request.body.attributeName && request.body.displayName) {
      let attributeExists = false;
      const attribute = {
        id: request.body.attributeName,
        optional: true,
        displayName: request.body.displayName,
        description: request.body.description || '',
        multiValue: request.body.valueType === 'multi'
      };

      request.metadata.forEach((entry: any) => {
        if (entry.id === request.body.attributeName) {
          entry = attribute;
          attributeExists = true;
        }
      });

      if (!attributeExists) {
        request.metadata.push(attribute);
      }

      response.status(200).end();
    }
  });

  app.get(IDP_PATHS.SIGN_OUT, (request: any, response, next) => {
    if (request.idp.options.sloUrl) {
      console.log('Initiating SAML SLO request for user: ' + request.user.userName +
      ' with sessionIndex: ' + getSessionIndex(request));
      response.redirect(IDP_PATHS.SLO);
    } else {
      console.log('SAML SLO is not enabled for SP, destroying IDP session');
      request.session.destroy((error: any) => {
        if (error) {
          throw error;
        }
        response.redirect('back');
      })
    }
  });

  app.get([IDP_PATHS.SETTINGS], (request: any, response, next) => {
    response.render('settings', {
      idp: request.idp.options
    });
  });

  app.post([IDP_PATHS.SETTINGS], (request: any, response, next) => {
    Object.keys(request.body).forEach(function(key) {
      switch(request.body[key].toLowerCase()){
        case "true": case "yes": case "1":
          request.idp.options[key] = true;
          break;
        case "false": case "no": case "0":
          request.idp.options[key] = false;
          break;
        default:
          request.idp.options[key] = request.body[key];
          break;
      }

      if (request.body[key].match(/^\d+$/)) {
        request.idp.options[key] = parseInt(request.body[key], 10);
      }
    });

    console.log('Updated IdP Configuration => \n', request.idp.options);
    response.redirect('/');
  });

  // catch 404 and forward to error handler
  app.use((request, response, next) => {
    const err = new Error('Route Not Found');
    // err.status = 404;
    next(err);
  });

  // development error handler
  app.use((error: any, request: any, response: any, next: express.NextFunction) => {
    if (error) {
      response.status(error.status || 500);
      response.render('error', {
          message: error.message,
          error: error
      });
    }
  });

  /**
   * Start IdP Web Server
   */
}