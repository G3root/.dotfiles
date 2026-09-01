/** Primary profile used by unit tests. Origins are fictional. */
export const PRIMARY_GATEWAY = {
	slot: "primary",
	id: "auth.example.test",
	name: "Private Gateway",
	authOrigin: "https://auth.example.test",
	gatewayOrigin: "https://gateway.example.test",
	tokenEnv: "PRIVATE_GATEWAY_PRIMARY_TOKEN",
};

/** Secondary profile used by unit tests. Origins are fictional. */
export const SECONDARY_GATEWAY = {
	slot: "secondary",
	id: "secondary.example.test",
	name: "Private Gateway 2",
	authOrigin: "https://secondary.example.test",
	gatewayOrigin: "https://secondary-gateway.example.test",
	tokenEnv: "PRIVATE_GATEWAY_SECONDARY_TOKEN",
};

/** Primary profile matching `fixtures/wellknown.json` origins. */
export const FIXTURE_PRIMARY_GATEWAY = {
	slot: "primary",
	id: "opencode.cloudflare.dev",
	name: "Private Gateway",
	authOrigin: "https://opencode.cloudflare.dev",
	gatewayOrigin: "https://gateway.opencode.cloudflare.dev",
	tokenEnv: "PRIVATE_GATEWAY_PRIMARY_TOKEN",
};

export const TEST_PROFILES = [PRIMARY_GATEWAY, SECONDARY_GATEWAY];
export const FIXTURE_PROFILES = [FIXTURE_PRIMARY_GATEWAY];
