import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGatewayDocument, resolveGatewayConfig } from "../discovery.ts";
import { excludeDuplicateGatewayModels, projectGatewayModels } from "../models.ts";
import { PRIMARY_GATEWAY, SECONDARY_GATEWAY } from "./profiles.mjs";

function project(profile, document) {
	const parsed = parseGatewayDocument(document, profile);
	assert.equal(parsed.ok, true);
	return projectGatewayModels(resolveGatewayConfig(parsed.value, profile));
}

test("secondary keeps only models the primary gateway does not already serve", () => {
	const primary = project(PRIMARY_GATEWAY, {
		enabled_providers: ["openai"],
		provider: {
			openai: {
				options: { baseURL: `${PRIMARY_GATEWAY.gatewayOrigin}/openai` },
				models: { "gpt-4o": {} },
			},
		},
	});
	const secondary = project(SECONDARY_GATEWAY, {
		enabled_providers: ["openai"],
		provider: {
			openai: {
				options: { baseURL: `${SECONDARY_GATEWAY.gatewayOrigin}/openai` },
				models: {
					"gpt-4o": {},
					"placeholder-secondary-model": { name: "Placeholder Secondary Model" },
				},
			},
		},
	});

	const exclusive = excludeDuplicateGatewayModels(secondary, primary);

	assert.ok(primary.some((model) => model.id === "gpt-4o"));
	assert.deepEqual(exclusive.map((model) => model.id), ["placeholder-secondary-model"]);
	assert.ok(exclusive.every((model) => model.provider === SECONDARY_GATEWAY.id));
});

test("secondary catalog is unchanged when the primary catalog is empty", () => {
	const secondary = project(SECONDARY_GATEWAY, {
		enabled_providers: ["openai"],
		provider: {
			openai: {
				options: { baseURL: `${SECONDARY_GATEWAY.gatewayOrigin}/openai` },
				models: { "placeholder-secondary-model": { name: "Placeholder Secondary Model" } },
			},
		},
	});

	const exclusive = excludeDuplicateGatewayModels(secondary, []);

	assert.deepEqual(exclusive.map((model) => model.id), secondary.map((model) => model.id));
});
