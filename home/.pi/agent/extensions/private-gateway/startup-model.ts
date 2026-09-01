import type { Api, Model } from "@earendil-works/pi-ai";

/** Pi thinking levels restored after startup selected no model. */
export type StartupThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max";

/** Observable outcome of private gateway startup model recovery. */
export type StartupModelRecoveryResult =
	| "recovered"
	| "not-needed"
	| "not-configured-default"
	| "catalog-unavailable"
	| "model-unavailable"
	| "auth-unavailable";

/** Dependencies needed to recover Pi's configured default after provider registration. */
export interface StartupModelRecoveryDependencies {
	readonly activeModel: Model<Api> | undefined;
	readonly defaultProvider: string | undefined;
	readonly defaultModelId: string | undefined;
	readonly defaultThinkingLevel: StartupThinkingLevel | undefined;
	/** Return whether the configured default provider is a loaded private gateway. */
	readonly isGatewayProvider: (providerId: string) => boolean;
	readonly refreshCachedCatalog: () => Promise<boolean>;
	readonly findModel: (provider: string, modelId: string) => Model<Api> | undefined;
	readonly setModel: (model: Model<Api>) => Promise<boolean>;
	readonly setThinkingLevel: (level: StartupThinkingLevel) => void;
}

/** Recover the configured private gateway default when Pi started before extension providers were registered. */
export async function recoverPrivateGatewayStartupModel(
	dependencies: StartupModelRecoveryDependencies,
): Promise<StartupModelRecoveryResult> {
	if (dependencies.activeModel) return "not-needed";
	const defaultProvider = dependencies.defaultProvider;
	if (!defaultProvider || !dependencies.isGatewayProvider(defaultProvider) || !dependencies.defaultModelId) {
		return "not-configured-default";
	}
	if (!(await dependencies.refreshCachedCatalog())) return "catalog-unavailable";

	const model = dependencies.findModel(defaultProvider, dependencies.defaultModelId);
	if (!model) return "model-unavailable";
	if (!(await dependencies.setModel(model))) return "auth-unavailable";

	dependencies.setThinkingLevel(dependencies.defaultThinkingLevel ?? "off");
	return "recovered";
}
