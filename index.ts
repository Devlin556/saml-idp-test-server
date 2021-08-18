import { runServer } from './src/index';

const main = async () => {
  const server = runServer({
    acsUrl: 'url',
		// fake
		audience: 'http://localhost:8080/auth/saml/metadata',
		cert: __dirname + '/idp-public-cert.pem',
		key: __dirname + '/idp-private-key.pem',
		issuer: 'issuer',
		serviceProviderId: 'issuer-2',
		config: {
			// The auth-service requires at least one AttributeStatement in the SAML assertion.
			user: {
				email: 'test@email.com',
			},
		},
  })
  console.log(server);
  
}

main()