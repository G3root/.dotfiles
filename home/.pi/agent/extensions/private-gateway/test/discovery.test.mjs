import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Redacted } from "../redacted.ts";
import { FIXTURE_PRIMARY_GATEWAY, SECONDARY_GATEWAY } from "./profiles.mjs";
import {
	fetchGatewayConfig,
	parseGatewayDocument,
	resolveGatewayConfig,
} from "../discovery.ts";
import { projectGatewayModels } from "../models.ts";

const fixturePath = fileURLToPath(new URL("./fixtures/wellknown.json", import.meta.url));
const fixtureText = readFileSync(fixturePath, "utf8");
const fixture = JSON.parse(fixtureText);

test("parses discovery into final native Pi models", () => {
	const parsed = parseGatewayDocument(fixture, FIXTURE_PRIMARY_GATEWAY);
	assert.equal(parsed.ok, true);
	const models = projectGatewayModels(resolveGatewayConfig(parsed.value, FIXTURE_PRIMARY_GATEWAY));
	const byId = new Map(models.map((model) => [model.id, model]));

	assert.ok(byId.has("gpt-4o"));
	assert.equal(byId.get("gpt-4o")?.api, "openai-responses");
	assert.equal(byId.get("gpt-4o")?.provider, "opencode.cloudflare.dev");
	assert.equal(byId.get("gpt-4o")?.baseUrl, "https://gateway.opencode.cloudflare.dev/openai");

	assert.ok(!byId.has("gpt-5.4-pro"));
	assert.ok(!byId.has("claude-opus-4-7-fast"));

	assert.ok(byId.has("workers-ai/@cf/moonshotai/kimi-k2.6"));
	assert.equal(byId.get("workers-ai/@cf/moonshotai/kimi-k2.6")?.api, "openai-completions");
	assert.equal(byId.get("workers-ai/@cf/moonshotai/kimi-k2.6")?.baseUrl, "https://gateway.opencode.cloudflare.dev/compat");

	assert.ok(byId.has("grok-4.5") || byId.has("grok-4.6"));
	const grok = [...byId.values()].find((model) => model.baseUrl.endsWith("/grok"));
	assert.ok(grok);
	assert.ok(grok.api === "openai-completions" || grok.api === "openai-responses");

	const opus = [...byId.values()].find((model) => model.id.includes("claude-opus") && model.api === "anthropic-messages");
	assert.ok(opus);
	assert.equal(opus.baseUrl, "https://gateway.opencode.cloudflare.dev/anthropic");
	assert.equal(opus.headers?.["anthropic-beta"], "context-1m-2025-08-07");
});

test("keeps discovery on the auth origin and inference on the gateway origin", () => {
	const parsed = parseGatewayDocument({
		remote_config: {
			url: "https://opencode.cloudflare.dev/config/opencode.json",
			headers: { "cf-access-token": "{env:TOKEN}" },
		},
		config: {
			provider: {
				openai: { options: { baseURL: "https://gateway.opencode.cloudflare.dev/openai" } },
			},
		},
	}, FIXTURE_PRIMARY_GATEWAY);
	assert.equal(parsed.ok, true);
	assert.equal(parsed.value.remoteConfig?.url, "https://opencode.cloudflare.dev/config/opencode.json");
	assert.equal(parsed.value.providers.openai?.baseUrl, "https://gateway.opencode.cloudflare.dev/openai");
});

test("rejects route URLs that could exfiltrate gateway credentials", () => {
	const parsed = parseGatewayDocument({
		config: {
			provider: {
				openai: { options: { baseURL: "https://attacker.example/openai" } },
			},
		},
	}, FIXTURE_PRIMARY_GATEWAY);
	assert.equal(parsed.ok, false);
	assert.match(parsed.error.message, /a URL on https:\/\/gateway\.opencode\.cloudflare\.dev/);
});

test("rejects untrusted remote configuration URLs", () => {
	const parsed = parseGatewayDocument({
		remote_config: {
			url: "https://attacker.example/config.json",
			headers: { "cf-access-token": "{env:TOKEN}" },
		},
	}, FIXTURE_PRIMARY_GATEWAY);
	assert.equal(parsed.ok, false);
	assert.match(parsed.error.message, /a URL on https:\/\/opencode\.cloudflare\.dev/);
});

test("rejects malformed known fields at the configuration boundary", () => {
	const parsed = parseGatewayDocument({
		config: {
			provider: {
				openai: { models: { broken: { reasoning: "yes" } } },
			},
		},
	}, FIXTURE_PRIMARY_GATEWAY);
	assert.equal(parsed.ok, false);
	assert.match(parsed.error.message, /broken\.reasoning/);
});

test("two-step discovery uses the supplied token only for the trusted remote config", async () => {
	const requests = [];
	const loaded = await fetchGatewayConfig({
		profile: FIXTURE_PRIMARY_GATEWAY,
		token: Redacted.make("context-token"),
		fetch: async (url, init) => {
			requests.push({ url, headers: new Headers(init.headers) });
			if (String(url).endsWith("/.well-known/opencode")) {
				return new Response(JSON.stringify({
					auth: { env: "TOKEN", command: ["cloudflared", "access", "login", "-app=https://opencode.cloudflare.dev"] },
					remote_config: {
						url: "https://opencode.cloudflare.dev/config/opencode.json",
						headers: { "cf-access-token": "{env:TOKEN}" },
					},
				}), { status: 200 });
			}
			return new Response(JSON.stringify({
				enabled_providers: ["openai"],
				provider: { openai: { models: { "gpt-4o": {} } } },
			}), { status: 200 });
		},
	});
	assert.equal(loaded.ok, true);
	assert.deepEqual(loaded.value.enabledBackends, ["openai"]);
	assert.equal(requests.length, 2);
	assert.equal(requests[1].headers.get("cf-access-token"), "context-token");
	assert.equal(loaded.value.routes.openai.baseUrl, "https://gateway.opencode.cloudflare.dev/openai");
});

test("discovery fetch observes cancellation", async () => {
	const controller = new AbortController();
	const pending = fetchGatewayConfig({
		profile: FIXTURE_PRIMARY_GATEWAY,
		signal: controller.signal,
		fetch: async (_url, init) => new Promise((_resolve, reject) => {
			init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
		}),
	});
	controller.abort();
	const loaded = await pending;
	assert.equal(loaded.ok, false);
	assert.equal(loaded.error.reason, "network");
});

test("unavailable discovery is a typed failure rather than a fallback catalog", async () => {
	const loaded = await fetchGatewayConfig({
		profile: FIXTURE_PRIMARY_GATEWAY,
		fetch: async () => new Response("unavailable", { status: 503, statusText: "Unavailable" }),
	});
	assert.equal(loaded.ok, false);
	assert.equal(loaded.error.reason, "http");
	assert.match(loaded.error.message, /503 Unavailable/);
});

test("secondary discovery stays on secondary auth and inference origins", () => {
	const parsed = parseGatewayDocument({
		remote_config: {
			url: `${SECONDARY_GATEWAY.authOrigin}/config/opencode.json`,
			headers: { "cf-access-token": "{env:TOKEN}" },
		},
		config: {
			provider: {
				anthropic: { options: { baseURL: `${SECONDARY_GATEWAY.gatewayOrigin}/anthropic` } },
			},
		},
	}, SECONDARY_GATEWAY);
	assert.equal(parsed.ok, true);
	assert.equal(parsed.value.remoteConfig?.url, `${SECONDARY_GATEWAY.authOrigin}/config/opencode.json`);
	assert.equal(parsed.value.providers.anthropic?.baseUrl, `${SECONDARY_GATEWAY.gatewayOrigin}/anthropic`);
	const config = resolveGatewayConfig(parsed.value, SECONDARY_GATEWAY);
	assert.equal(config.providerId, SECONDARY_GATEWAY.id);
	assert.equal(config.origin, SECONDARY_GATEWAY.gatewayOrigin);
});

test("secondary discovery rejects primary inference URLs", () => {
	const parsed = parseGatewayDocument({
		config: {
			provider: {
				anthropic: { options: { baseURL: `${FIXTURE_PRIMARY_GATEWAY.gatewayOrigin}/anthropic` } },
			},
		},
	}, SECONDARY_GATEWAY);
	assert.equal(parsed.ok, false);
	assert.match(parsed.error.message, new RegExp(`a URL on ${SECONDARY_GATEWAY.gatewayOrigin.replaceAll(".", "\\.")}`));
});

test("secondary discovery rejects primary auth remote configuration URLs", () => {
	const parsed = parseGatewayDocument({
		remote_config: {
			url: `${FIXTURE_PRIMARY_GATEWAY.authOrigin}/config/opencode.json`,
			headers: { "cf-access-token": "{env:TOKEN}" },
		},
	}, SECONDARY_GATEWAY);
	assert.equal(parsed.ok, false);
	assert.match(parsed.error.message, new RegExp(`a URL on ${SECONDARY_GATEWAY.authOrigin.replaceAll(".", "\\.")}`));
});

test("secondary two-step discovery fetches the secondary well-known document", async () => {
	const requests = [];
	const loaded = await fetchGatewayConfig({
		profile: SECONDARY_GATEWAY,
		token: Redacted.make("secondary-token"),
		fetch: async (url, init) => {
			requests.push({ url: String(url), headers: new Headers(init.headers) });
			if (String(url) === `${SECONDARY_GATEWAY.authOrigin}/.well-known/opencode`) {
				return new Response(JSON.stringify({
					auth: { env: "TOKEN", command: ["cloudflared", "access", "login", `-app=${SECONDARY_GATEWAY.authOrigin}`] },
					remote_config: {
						url: `${SECONDARY_GATEWAY.authOrigin}/config/opencode.json`,
						headers: { "cf-access-token": "{env:TOKEN}" },
					},
				}), { status: 200 });
			}
			return new Response(JSON.stringify({
				enabled_providers: ["anthropic"],
				provider: {
					anthropic: {
						options: { baseURL: `${SECONDARY_GATEWAY.gatewayOrigin}/anthropic` },
						models: { "placeholder-secondary-model": { name: "Placeholder Secondary Model" } },
					},
				},
			}), { status: 200 });
		},
	});
	assert.equal(loaded.ok, true);
	assert.equal(requests[0]?.url, `${SECONDARY_GATEWAY.authOrigin}/.well-known/opencode`);
	assert.equal(requests[1]?.url, `${SECONDARY_GATEWAY.authOrigin}/config/opencode.json`);
	assert.equal(requests[1]?.headers.get("cf-access-token"), "secondary-token");
	assert.equal(loaded.value.providerId, SECONDARY_GATEWAY.id);
	assert.equal(loaded.value.routes.anthropic.baseUrl, `${SECONDARY_GATEWAY.gatewayOrigin}/anthropic`);
	const models = projectGatewayModels(loaded.value);
	assert.ok(models.some((model) => model.id === "placeholder-secondary-model"));
	assert.ok(models.every((model) => model.provider === SECONDARY_GATEWAY.id));
});
