import fs from 'fs'
import yargs from 'yargs'

import { KEY_CERT_HELP_TEXT } from './constants';
import { makeCertFileCoercer, resolveFilePath } from './helpers';
import { SamlIdpMockServerOptions } from './server';

export const processArgs = (args: any, options: SamlIdpMockServerOptions) => {
  var baseArgv;

  if (options) {
    baseArgv = yargs(args).config(options);
  } else {
    baseArgv = yargs(args);
  }

  return baseArgv
    .usage('\nSimple IdP for SAML 2.0 WebSSO & SLO Profile\n\n' +
        'Launches an IdP web server that mints SAML assertions or logout responses for a Service Provider (SP)\n\n' +
        'Usage:\n\t$0 --acsUrl {url} --audience {uri}')
    .alias({h: 'help'})
    .options({
      host: {
        description: 'IdP Web Server Listener Host',
        required: false,
        default: 'localhost'
      },
      port: {
        description: 'IdP Web Server Listener Port',
        required: true,
        alias: 'p',
        default: 7000
      },
      cert: {
        description: 'IdP Signature PublicKey Certificate',
        required: true,
        default: './idp-public-cert.pem',
        coerce: makeCertFileCoercer('certificate', 'IdP Signature PublicKey Certificate', KEY_CERT_HELP_TEXT)
      },
      key: {
        description: 'IdP Signature PrivateKey Certificate',
        required: true,
        default: './idp-private-key.pem',
        coerce: makeCertFileCoercer('RSA private key', 'IdP Signature PrivateKey Certificate', KEY_CERT_HELP_TEXT)
      },
      issuer: {
        description: 'IdP Issuer URI',
        required: true,
        alias: 'iss',
        default: 'urn:example:idp'
      },
      acsUrl: {
        description: 'SP Assertion Consumer URL',
        required: true,
        alias: 'acs'
      },
      sloUrl: {
        description: 'SP Single Logout URL',
        required: false,
        alias: 'slo'
      },
      audience: {
        description: 'SP Audience URI',
        required: true,
        alias: 'aud'
      },
      serviceProviderId: {
        description: 'SP Issuer/Entity URI',
        required: false,
        alias: 'spId',
        string: true
      },
      relayState: {
        description: 'Default SAML RelayState for SAMLResponse',
        required: false,
        alias: 'rs'
      },
      disableRequestAcsUrl: {
        description: 'Disables ability for SP AuthnRequest to specify Assertion Consumer URL',
        required: false,
        boolean: true,
        alias: 'static',
        default: false
      },
      encryptAssertion: {
        description: 'Encrypts assertion with SP Public Key',
        required: false,
        boolean: true,
        alias: 'enc',
        default: false
      },
      encryptionCert: {
        description: 'SP Certificate (pem) for Assertion Encryption',
        required: false,
        string: true,
        alias: 'encCert',
        coerce: makeCertFileCoercer('certificate', 'Encryption cert')
      },
      encryptionPublicKey: {
        description: 'SP RSA Public Key (pem) for Assertion Encryption ' +
        '(e.g. openssl x509 -pubkey -noout -in sp-cert.pem)',
        required: false,
        string: true,
        alias: 'encKey',
        coerce: makeCertFileCoercer('public key', 'Encryption public key')
      },
      httpsPrivateKey: {
        description: 'Web Server TLS/SSL Private Key (pem)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('RSA private key')
      },
      httpsCert: {
        description: 'Web Server TLS/SSL Certificate (pem)',
        required: false,
        string: true,
        coerce: makeCertFileCoercer('certificate')
      },
      https: {
        description: 'Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)',
        required: true,
        boolean: true,
        default: false
      },
      signResponse: {
        description: 'Enables signing of responses',
        required: false,
        boolean: true,
        default: true,
        alias: 'signResponse'
      },
      configFile: {
        description: 'Path to a SAML attribute config file',
        required: true,
        default: 'saml-idp/config.js',
        alias: 'conf'
      },
      rollSession: {
        description: 'Create a new session for every authn request instead of reusing an existing session',
        required: false,
        boolean: true,
        default: false
      },
      authnContextClassRef: {
        description: 'Authentication Context Class Reference',
        required: false,
        string: true,
        default: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        alias: 'acr'
      },
      authnContextDecl: {
        description: 'Authentication Context Declaration (XML FilePath)',
        required: false,
        string: true,
        alias: 'acd',
        coerce: (value: string) => {
          const filePath = resolveFilePath(value);
          if (filePath) {
            return fs.readFileSync(filePath, 'utf8')
          } else {
            return null
          }
        }
      }
    })
    .example('$0 --acsUrl http://acme.okta.com/auth/saml20/exampleidp --audience https://www.okta.com/saml2/service-provider/spf5aFRRXFGIMAYXQPNV', '')
    .check(function(argv, aliases) {
      if (argv.encryptAssertion) {
        if (argv.encryptionPublicKey === undefined) {
          return 'encryptionPublicKey argument is also required for assertion encryption';
        }
        if (argv.encryptionCert === undefined) {
          return 'encryptionCert argument is also required for assertion encryption';
        }
      }
      return true;
    })
    .check(function(argv, aliases) {
      if (argv.config) {
        return true;
      }
      const configFilePath = resolveFilePath(argv.configFile);

      if (!configFilePath) {
        return 'SAML attribute config file path "' + argv.configFile + '" is not a valid path.\n';
      }
      try {
        argv.config = require(configFilePath);
      } catch (error) {
        return 'Encountered an exception while loading SAML attribute config file "' + configFilePath + '".\n' + error;
      }
      return true;
    })
    .wrap(baseArgv.terminalWidth());
}