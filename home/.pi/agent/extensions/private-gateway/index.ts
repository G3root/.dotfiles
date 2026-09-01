import {
	getAgentDir,
	SettingsManager,
	type ExtensionAPI,
	type ExtensionCommandContext,
	type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { createProductionOpenCodeAuthSource } from "./auth.ts";
import { buildDoctorReport } from "./doctor.ts";
import {
	findPrivateGatewayProfile,
	isPrivateGatewayProviderId,
	parsePrivateGatewayProfiles,
	type GatewayProfile,
} from "./private-gateway-profiles.ts";
import { createPrivateGatewayProvider } from "./provider.ts";
import { createGatewayMessageEndHandler } from "./redact-gateway-secrets.ts";
import { recoverPrivateGatewayStartupModel } from "./startup-model.ts";

const STARTUP_CATALOG_TIMEOUT_MS = 5_000;

async function handleDoctor(
	ctx: ExtensionCommandContext,
	profiles: readonly GatewayProfile[],
): Promise<void> {
	const piAuthStatuses = Object.fromEntries(
		profiles.map((profile) => {
			const status = ctx.modelRegistry.getProviderAuthStatus(profile.id);
			return [profile.id, status.configured ? status.source ?? status.label ?? "configured" : "missing"] as const;
		}),
	);
	const report = await buildDoctorReport({ profiles, piAuthStatuses });
	ctx.ui.notify(report, "info");
}

async function recoverStartupDefaultModel(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	profiles: readonly GatewayProfile[],
): Promise<void> {
	const settings = SettingsManager.create(ctx.cwd, getAgentDir(), { projectTrusted: ctx.isProjectTrusted() });
	const defaultProvider = settings.getDefaultProvider();
	const profile = defaultProvider ? findPrivateGatewayProfile(profiles, defaultProvider) : undefined;
	const result = await recoverPrivateGatewayStartupModel({
		activeModel: ctx.model,
		defaultProvider,
		defaultModelId: settings.getDefaultModel(),
		defaultThinkingLevel: settings.getDefaultThinkingLevel(),
		isGatewayProvider: (providerId) => isPrivateGatewayProviderId(profiles, providerId),
		refreshCachedCatalog: async () => {
			if (!defaultProvider) return false;
			try {
				const refresh = await ctx.modelRegistry.refresh({
					providers: [defaultProvider],
					allowNetwork: false,
					signal: AbortSignal.timeout(STARTUP_CATALOG_TIMEOUT_MS),
				});
				return !refresh.aborted && !refresh.errors.has(defaultProvider);
			} catch {
				return false;
			}
		},
		findModel: (provider, modelId) => ctx.modelRegistry.find(provider, modelId),
		setModel: (model) => pi.setModel(model),
		setThinkingLevel: (level) => pi.setThinkingLevel(level),
	});

	const label = profile?.name ?? "Private Gateway";
	if (result === "catalog-unavailable") {
		ctx.ui.notify(`${label} startup recovery: cached model catalog is unavailable`, "warning");
	} else if (result === "model-unavailable") {
		ctx.ui.notify(`${label} startup recovery: configured default model is unavailable`, "warning");
	} else if (result === "auth-unavailable") {
		ctx.ui.notify(`${label} startup recovery: provider authentication is unavailable`, "warning");
	}
}

/**
 * Register private gateway providers when profile environment variables are present.
 *
 * @param pi - Pi extension API.
 */
export default function registerPrivateGateway(pi: ExtensionAPI): void {
	const parsed = parsePrivateGatewayProfiles((name) => process.env[name]);
	if (!parsed.ok || parsed.value.length === 0) return;
	const profiles = parsed.value;
	const authSource = createProductionOpenCodeAuthSource(profiles.map((profile) => profile.authOrigin));
	for (const profile of profiles) {
		pi.registerProvider(createPrivateGatewayProvider({ profile, profiles, authSource }));
	}
	pi.on("session_start", async (_event, ctx) => recoverStartupDefaultModel(pi, ctx, profiles));
	pi.on("message_end", createGatewayMessageEndHandler(profiles));
	pi.registerCommand("private-gateway-doctor", {
		description: "Validate private gateway authentication and gateway health",
		handler: async (_args, ctx) => handleDoctor(ctx, profiles),
	});
}
