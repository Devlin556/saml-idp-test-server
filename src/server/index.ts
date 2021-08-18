import chalk from 'chalk';
import express from 'express';
import http from 'http';
import https from 'https';
import { DOMParser as Parser } from 'xmldom'
import os from 'os';

import { IDP_PATHS, WILDCARD_ADDRESSES } from '../constants';
import SimpleProfileMapper from './profile-mapper';
import { configureRoutes } from './routes';
import { dedent } from '../helpers';

export interface SamlUser {
	email: string
}

export interface SamlIdpMockServerConfig {
	user: SamlUser
  metadata?: any
}

export interface SamlIdpMockServerOptions {
	acsUrl: string;
	audience: string;
	issuer: string;
	serviceProviderId: string;
	cert: string;
	key: string;
	config: SamlIdpMockServerConfig
  https?: boolean
  httpsPrivateKey?: string
  httpsCert?: string
  recipient?: string
  destination?: string
  sloUrl?: string
  RelayState?: string
  allowRequestAcsUrl?: string
  digestAlgorithm?: string
  signatureAlgorithm?: string
  signResponse?: string
  encryptAssertion?: string
  encryptionCert?: string
  encryptionPublicKey?: string
  encryptionAlgorithm?: string
  keyEncryptionAlgorithm?: string
  lifetimeInSeconds?: string
  authnContextClassRef?: string
  authnContextDecl?: string
  includeAttributeNameFormat?: string
  profileMapper?: string
  postEndpointPath?: string
  redirectEndpointPath?: string
  logoutEndpointPaths?: string
  relayState?: string
  disableRequestAcsUrl?: boolean
}

export const runServer = (options: SamlIdpMockServerOptions) => {
  const app = express();
  const httpServer = options.https ?
    https.createServer({ key: options.httpsPrivateKey, cert: options.httpsCert }, app) :
    http.createServer(app);
  const blocks = {};

  const idpOptions = {
    issuer: options.issuer,
    serviceProviderId: options.serviceProviderId || options.audience,
    cert: options.cert,
    key: options.key,
    audience: options.audience,
    recipient: options.acsUrl,
    destination: options.acsUrl,
    acsUrl: options.acsUrl,
    sloUrl: options.sloUrl,
    RelayState: options.relayState,
    allowRequestAcsUrl: !options.disableRequestAcsUrl,
    digestAlgorithm: 'sha256',
    signatureAlgorithm: 'rsa-sha256',
    signResponse: options.signResponse,
    encryptAssertion: options.encryptAssertion,
    encryptionCert: options.encryptionCert,
    encryptionPublicKey: options.encryptionPublicKey,
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    lifetimeInSeconds: 3600,
    authnContextClassRef: options.authnContextClassRef,
    authnContextDecl: options.authnContextDecl,
    includeAttributeNameFormat: true,
    profileMapper: SimpleProfileMapper.fromMetadata(options.config.metadata),
    postEndpointPath: IDP_PATHS.SSO,
    redirectEndpointPath: IDP_PATHS.SSO,
    logoutEndpointPaths: options.sloUrl ? { redirect: IDP_PATHS.SLO, post: IDP_PATHS.SLO} : {},
    getUserFromRequest: (request: any) => { return request.user; },
    getPostURL: (audience: string, authnRequestDom: any, req: any, callback: any) => {
      return callback(null, (req.authnRequest && req.authnRequest.acsUrl) ?
        req.authnRequest.acsUrl :
        req.idp.options.acsUrl);
    },
    transformAssertion: (assertionDom: any) => {
      if (options.authnContextDecl) {
        let declDoc;
        try {
          declDoc = new Parser().parseFromString(options.authnContextDecl);
        } catch(err){
          console.log('Unable to parse Authentication Context Declaration XML', err);
        }
        if (declDoc) {
          const authnContextDeclEl = assertionDom.createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextDecl');
          authnContextDeclEl.appendChild(declDoc.documentElement);
          const authnContextEl = assertionDom.getElementsByTagName('saml:AuthnContext')[0];
          authnContextEl.appendChild(authnContextDeclEl);
        }
      }
    },
    responseHandler:(response: any, opts: any, request: any, res: any, next: any) => {
      res.render('samlresponse', {
        AcsUrl: opts.postUrl,
        SAMLResponse: response.toString('base64'),
        RelayState: opts.RelayState
      });
    }
  }

  configureRoutes({ app, argv: idpOptions, hbsBlocks: blocks, idpOptions })

  console.log(chalk`Starting IdP server on port {cyan ${app.get('host')}:${app.get('port')}}...\n`);

  httpServer.listen(app.get('port'), app.get('host'), function() {
    const scheme = options.https ? 'https' : 'http';
    const { address, port } = httpServer.address() as any;
    const hostname = WILDCARD_ADDRESSES.includes(address) ? os.hostname() : 'localhost';
    const baseUrl = `${scheme}://${hostname}:${port}`;

    console.log(dedent(chalk`
      IdP Metadata URL:
        {cyan ${baseUrl}${IDP_PATHS.METADATA}}
    `))
  });

  return httpServer
}