import assert from "node:assert/strict";
import { test } from "node:test";
import { recoverPrivateGatewayStartupModel } from "../startup-model.ts";
import { PRIMARY_GATEWAY, SECONDARY_GATEWAY } from "./profiles.mjs";

const defaultModel = {
	id: "public-default-model",
	provider: PRIMARY_GATEWAY.id,
};

function createDependencies(overrides = {}) {
	const calls = [];
	return {
		calls,
		dependencies: {
			activeModel: undefined,
			defaultProvider: PRIMARY_GATEWAY.id,
			defaultModelId: defaultModel.id,
			defaultThinkingLevel: "medium",
			isGatewayProvider: (providerId) => providerId === PRIMARY_GATEWAY.id || providerId === SECONDARY_GATEWAY.id,
			refreshCachedCatalog: async () => {
				calls.push("refresh");
				return true;
			},
			findModel: (provider, modelId) => {
				calls.push(`find:${provider}/${modelId}`);
				return defaultModel;
			},
			setModel: async (model) => {
				calls.push(`set:${model.provider}/${model.id}`);
				return true;
			},
			setThinkingLevel: (level) => {
				calls.push(`thinking:${level}`);
			},
			...overrides,
		},
	};
}

test("recovers the configured default model from the cached catalog", async () => {
	const { calls, dependencies } = createDependencies();

	const result = await recoverPrivateGatewayStartupModel(dependencies);

	assert.equal(result, "recovered");
	assert.deepEqual(calls, [
		"refresh",
		`find:${PRIMARY_GATEWAY.id}/public-default-model`,
		`set:${PRIMARY_GATEWAY.id}/public-default-model`,
		"thinking:medium",
	]);
});

test("leaves an already selected model unchanged", async () => {
	const { calls, dependencies } = createDependencies({ activeModel: defaultModel });

	const result = await recoverPrivateGatewayStartupModel(dependencies);

	assert.equal(result, "not-needed");
	assert.deepEqual(calls, []);
});

test("recovers a secondary default model from the cached catalog", async () => {
	const secondaryModel = {
		id: "public-secondary-default-model",
		provider: SECONDARY_GATEWAY.id,
	};
	const { calls, dependencies } = createDependencies({
		defaultProvider: SECONDARY_GATEWAY.id,
		defaultModelId: secondaryModel.id,
		findModel: (provider, modelId) => {
			calls.push(`find:${provider}/${modelId}`);
			return secondaryModel;
		},
		setModel: async (model) => {
			calls.push(`set:${model.provider}/${model.id}`);
			return true;
		},
	});

	const result = await recoverPrivateGatewayStartupModel(dependencies);

	assert.equal(result, "recovered");
	assert.deepEqual(calls, [
		"refresh",
		`find:${SECONDARY_GATEWAY.id}/public-secondary-default-model`,
		`set:${SECONDARY_GATEWAY.id}/public-secondary-default-model`,
		"thinking:medium",
	]);
});

test("does not select a model for another configured provider", async () => {
	const { calls, dependencies } = createDependencies({ defaultProvider: "anthropic" });

	const result = await recoverPrivateGatewayStartupModel(dependencies);

	assert.equal(result, "not-configured-default");
	assert.deepEqual(calls, []);
});

test("reports a missing cached default model without changing session state", async () => {
	const { calls, dependencies } = createDependencies({
		findModel: (provider, modelId) => {
			calls.push(`find:${provider}/${modelId}`);
			return undefined;
		},
	});

	const result = await recoverPrivateGatewayStartupModel(dependencies);

	assert.equal(result, "model-unavailable");
	assert.deepEqual(calls, ["refresh", `find:${PRIMARY_GATEWAY.id}/public-default-model`]);
});

test("does not change thinking when model authentication is unavailable", async () => {
	const { calls, dependencies } = createDependencies({
		setModel: async (model) => {
			calls.push(`set:${model.provider}/${model.id}`);
			return false;
		},
	});

	const result = await recoverPrivateGatewayStartupModel(dependencies);

	assert.equal(result, "auth-unavailable");
	assert.deepEqual(calls, [
		"refresh",
		`find:${PRIMARY_GATEWAY.id}/public-default-model`,
		`set:${PRIMARY_GATEWAY.id}/public-default-model`,
	]);
});
