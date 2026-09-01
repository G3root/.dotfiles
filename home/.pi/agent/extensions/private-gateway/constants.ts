/** Gateway backend identifiers supported by a private inference gateway. */
export const BACKENDS = ["anthropic", "openai", "google", "xai", "workers-ai"] as const;

/** Gateway backend identifier. */
export type Backend = (typeof BACKENDS)[number];

/** Gateway discovery document path. */
export const WELL_KNOWN_PATH = "/.well-known/opencode";

/** Fallback lifetime for opaque tokens without a JWT expiry. */
export const DEFAULT_TOKEN_EXPIRY_MS = 12 * 60 * 60 * 1000;

/** Safety margin subtracted from JWT expiry timestamps. */
export const EXPIRY_SAFETY_BUFFER_MS = 5 * 60 * 1000;

/** Discovery and remote-config request timeout. */
export const DISCOVERY_TIMEOUT_MS = 10_000;

/**
 * Return the well-known discovery URL for a gateway auth origin.
 *
 * @param authOrigin - Origin that hosts `/.well-known/opencode`.
 */
export function gatewayWellKnownUrl(authOrigin: string): string {
	return `${authOrigin}${WELL_KNOWN_PATH}`;
}

/**
 * Return the default backend URLs for an inference origin.
 *
 * @param gatewayOrigin - Trusted inference gateway origin.
 */
export function defaultGatewayRouteUrls(gatewayOrigin: string): Readonly<Record<Backend, string>> {
	return {
		anthropic: `${gatewayOrigin}/anthropic`,
		openai: `${gatewayOrigin}/openai`,
		google: `${gatewayOrigin}/google-ai-studio/v1beta`,
		xai: `${gatewayOrigin}/grok`,
		"workers-ai": `${gatewayOrigin}/compat`,
	};
}
