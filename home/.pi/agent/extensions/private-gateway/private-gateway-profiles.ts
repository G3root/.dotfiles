import { failure, type Result, success } from "./result.ts";

/** Private gateway slot loaded from the environment. */
export type GatewaySlot = "primary" | "secondary";

/** Trusted private-gateway Access application registered as a Pi provider. */
export interface GatewayProfile {
	/** Environment slot this profile was parsed from. */
	readonly slot: GatewaySlot;
	/** Pi provider identifier registered for this Access application. */
	readonly id: string;
	/** Human-readable provider name shown in `/login`. */
	readonly name: string;
	/** Identity-aware proxy authentication and well-known discovery origin. */
	readonly authOrigin: string;
	/** Inference gateway origin. */
	readonly gatewayOrigin: string;
	/** Process environment variable that may supply this gateway's access token. */
	readonly tokenEnv: string;
}

/** Environment variable for the primary gateway authentication origin. */
export const PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN_ENV = "PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN";
/** Environment variable for the primary gateway inference origin. */
export const PRIVATE_GATEWAY_PRIMARY_GATEWAY_ORIGIN_ENV = "PRIVATE_GATEWAY_PRIMARY_GATEWAY_ORIGIN";
/** Environment variable for the primary gateway `/login` display name. */
export const PRIVATE_GATEWAY_PRIMARY_NAME_ENV = "PRIVATE_GATEWAY_PRIMARY_NAME";
/** Environment variable that may supply the primary gateway access token. */
export const PRIVATE_GATEWAY_PRIMARY_TOKEN_ENV = "PRIVATE_GATEWAY_PRIMARY_TOKEN";
/** Environment variable for the secondary gateway authentication origin. */
export const PRIVATE_GATEWAY_SECONDARY_AUTH_ORIGIN_ENV = "PRIVATE_GATEWAY_SECONDARY_AUTH_ORIGIN";
/** Environment variable for the secondary gateway inference origin. */
export const PRIVATE_GATEWAY_SECONDARY_GATEWAY_ORIGIN_ENV = "PRIVATE_GATEWAY_SECONDARY_GATEWAY_ORIGIN";
/** Environment variable for the secondary gateway `/login` display name. */
export const PRIVATE_GATEWAY_SECONDARY_NAME_ENV = "PRIVATE_GATEWAY_SECONDARY_NAME";
/** Environment variable that may supply the secondary gateway access token. */
export const PRIVATE_GATEWAY_SECONDARY_TOKEN_ENV = "PRIVATE_GATEWAY_SECONDARY_TOKEN";
/** Environment variable overriding the imported auth-file path. */
export const PRIVATE_GATEWAY_AUTH_FILE_ENV = "PRIVATE_GATEWAY_AUTH_FILE";

/** Structured failure while parsing private gateway profile environment variables. */
export class PrivateGatewayProfileError extends Error {
	readonly _tag = "PrivateGatewayProfileError" as const;

	/**
	 * Create a profile configuration failure.
	 *
	 * @param reason - Stable configuration failure classification.
	 * @param detail - Safe user-facing detail.
	 */
	constructor(
		readonly reason: "incomplete-slot" | "invalid-origin",
		readonly detail: string,
	) {
		super(`Invalid private gateway profile: ${detail}`);
		this.name = "PrivateGatewayProfileError";
	}
}

function readOptional(environment: (name: string) => string | undefined, name: string): string | undefined {
	const value = environment(name)?.trim();
	return value ? value : undefined;
}

function parseHttpsOrigin(input: string, variable: string): Result<string, PrivateGatewayProfileError> {
	try {
		const url = new URL(input);
		if (url.protocol !== "https:") {
			return failure(new PrivateGatewayProfileError("invalid-origin", `${variable} must be an https origin`));
		}
		return success(url.origin);
	} catch {
		return failure(new PrivateGatewayProfileError("invalid-origin", `${variable} must be an https origin`));
	}
}

function parseSlot(
	environment: (name: string) => string | undefined,
	slot: GatewaySlot,
	authVariable: string,
	gatewayVariable: string,
	nameVariable: string,
	tokenEnv: string,
	defaultName: string,
): Result<GatewayProfile | undefined, PrivateGatewayProfileError> {
	const authInput = readOptional(environment, authVariable);
	const gatewayInput = readOptional(environment, gatewayVariable);
	if (!authInput && !gatewayInput) return success(undefined);
	if (!authInput || !gatewayInput) {
		return failure(new PrivateGatewayProfileError(
			"incomplete-slot",
			`${slot} requires both ${authVariable} and ${gatewayVariable}`,
		));
	}
	const authOrigin = parseHttpsOrigin(authInput, authVariable);
	if (!authOrigin.ok) return authOrigin;
	const gatewayOrigin = parseHttpsOrigin(gatewayInput, gatewayVariable);
	if (!gatewayOrigin.ok) return gatewayOrigin;
	return success({
		slot,
		id: new URL(authOrigin.value).host,
		name: readOptional(environment, nameVariable) ?? defaultName,
		authOrigin: authOrigin.value,
		gatewayOrigin: gatewayOrigin.value,
		tokenEnv,
	});
}

/**
 * Parse primary and secondary private gateway profiles from the process environment.
 *
 * Missing primary origins yield an empty list so the extension can stay unloaded.
 * A present but incomplete or invalid slot is a typed configuration failure.
 *
 * @param environment - Environment lookup, usually `process.env`.
 */
export function parsePrivateGatewayProfiles(
	environment: (name: string) => string | undefined,
): Result<readonly GatewayProfile[], PrivateGatewayProfileError> {
	const primary = parseSlot(
		environment,
		"primary",
		PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN_ENV,
		PRIVATE_GATEWAY_PRIMARY_GATEWAY_ORIGIN_ENV,
		PRIVATE_GATEWAY_PRIMARY_NAME_ENV,
		PRIVATE_GATEWAY_PRIMARY_TOKEN_ENV,
		"Private Gateway",
	);
	if (!primary.ok) return primary;
	if (!primary.value) {
		const secondaryOnly = parseSlot(
			environment,
			"secondary",
			PRIVATE_GATEWAY_SECONDARY_AUTH_ORIGIN_ENV,
			PRIVATE_GATEWAY_SECONDARY_GATEWAY_ORIGIN_ENV,
			PRIVATE_GATEWAY_SECONDARY_NAME_ENV,
			PRIVATE_GATEWAY_SECONDARY_TOKEN_ENV,
			"Private Gateway 2",
		);
		if (!secondaryOnly.ok) return secondaryOnly;
		if (secondaryOnly.value) {
			return failure(new PrivateGatewayProfileError(
				"incomplete-slot",
				`secondary requires ${PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN_ENV} and ${PRIVATE_GATEWAY_PRIMARY_GATEWAY_ORIGIN_ENV}`,
			));
		}
		return success([]);
	}
	const secondary = parseSlot(
		environment,
		"secondary",
		PRIVATE_GATEWAY_SECONDARY_AUTH_ORIGIN_ENV,
		PRIVATE_GATEWAY_SECONDARY_GATEWAY_ORIGIN_ENV,
		PRIVATE_GATEWAY_SECONDARY_NAME_ENV,
		PRIVATE_GATEWAY_SECONDARY_TOKEN_ENV,
		"Private Gateway 2",
	);
	if (!secondary.ok) return secondary;
	return success(secondary.value ? [primary.value, secondary.value] : [primary.value]);
}

/**
 * Return the profile registered under a Pi provider id.
 *
 * @param profiles - Parsed private gateway profiles.
 * @param providerId - Pi provider identifier.
 */
export function findPrivateGatewayProfile(
	profiles: readonly GatewayProfile[],
	providerId: string,
): GatewayProfile | undefined {
	return profiles.find((profile) => profile.id === providerId);
}

/**
 * Return whether a Pi provider id belongs to a parsed private gateway profile.
 *
 * @param profiles - Parsed private gateway profiles.
 * @param providerId - Pi provider identifier.
 */
export function isPrivateGatewayProviderId(profiles: readonly GatewayProfile[], providerId: string): boolean {
	return findPrivateGatewayProfile(profiles, providerId) !== undefined;
}

/**
 * Return the primary private gateway profile when one was configured.
 *
 * @param profiles - Parsed private gateway profiles.
 */
export function findPrimaryGatewayProfile(profiles: readonly GatewayProfile[]): GatewayProfile | undefined {
	return profiles.find((profile) => profile.slot === "primary");
}
