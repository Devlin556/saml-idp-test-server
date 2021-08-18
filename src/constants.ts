import chalk from 'chalk';

import { dedent } from './helpers';

export const IDP_PATHS = {
  SSO: '/saml/sso',
  SLO: '/saml/slo',
  METADATA: '/metadata',
  SIGN_IN: '/signin',
  SIGN_OUT: '/signout',
  SETTINGS: '/settings'
}

export const CERT_OPTIONS = [
  'cert',
  'key',
  'encryptionCert',
  'encryptionPublicKey',
  'httpsPrivateKey',
  'httpsCert',
];

export const WILDCARD_ADDRESSES = ['0.0.0.0', '::'];

export const UNDEFINED_VALUE = 'None';

export const CRYPT_TYPES = {
  certificate: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/,
  'RSA private key': /-----BEGIN RSA PRIVATE KEY-----\n[^-]*\n-----END RSA PRIVATE KEY-----/,
  'public key': /-----BEGIN PUBLIC KEY-----\n[^-]*\n-----END PUBLIC KEY-----/,
};

export const KEY_CERT_HELP_TEXT = dedent(chalk`
To generate a key/cert pair for the IdP, run the following command:

{gray openssl req -x509 -new -newkey rsa:2048 -nodes \
-subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' \
-keyout idp-private-key.pem \
-out idp-public-cert.pem -days 7300}`
);

export type CRYPT_TYPES_KEYS = keyof typeof CRYPT_TYPES;

export type CERT_OPTIONS_KEYS = 'cert' | 'key' | 'encryptionCert' | 'encryptionPublicKey' | 'httpsPrivateKey' | 'httpsCert'