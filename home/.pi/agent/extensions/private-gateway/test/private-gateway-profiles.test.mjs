import assert from "node:assert/strict";
import { test } from "node:test";
import {
	parsePrivateGatewayProfiles,
	PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN_ENV,
	PRIVATE_GATEWAY_PRIMARY_GATEWAY_ORIGIN_ENV,
	PRIVATE_GATEWAY_PRIMARY_NAME_ENV,
	PRIVATE_GATEWAY_SECONDARY_AUTH_ORIGIN_ENV,
	PRIVATE_GATEWAY_SECONDARY_GATEWAY_ORIGIN_ENV,
} from "../private-gateway-profiles.ts";

function env(entries) {
	const values = new Map(Object.entries(entries));
	return (name) => values.get(name);
}

test("missing primary origins yield no profiles so the extension can stay unloaded", () => {
	const parsed = parsePrivateGatewayProfiles(env({}));
	assert.equal(parsed.ok, true);
	assert.deepEqual(parsed.value, []);
});

test("parses primary and secondary https origins into gateway profiles", () => {
	const parsed = parsePrivateGatewayProfiles(env({
		[PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN_ENV]: "https://auth.example.test/path",
		[PRIVATE_GATEWAY_PRIMARY_GATEWAY_ORIGIN_ENV]: "https://gateway.example.test",
		[PRIVATE_GATEWAY_PRIMARY_NAME_ENV]: "Private Gateway",
		[PRIVATE_GATEWAY_SECONDARY_AUTH_ORIGIN_ENV]: "https://secondary.example.test",
		[PRIVATE_GATEWAY_SECONDARY_GATEWAY_ORIGIN_ENV]: "https://secondary-gateway.example.test",
	}));
	assert.equal(parsed.ok, true);
	assert.equal(parsed.value.length, 2);
	assert.equal(parsed.value[0].slot, "primary");
	assert.equal(parsed.value[0].id, "auth.example.test");
	assert.equal(parsed.value[0].authOrigin, "https://auth.example.test");
	assert.equal(parsed.value[0].gatewayOrigin, "https://gateway.example.test");
	assert.equal(parsed.value[1].slot, "secondary");
	assert.equal(parsed.value[1].id, "secondary.example.test");
});

test("rejects an incomplete primary slot", () => {
	const parsed = parsePrivateGatewayProfiles(env({
		[PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN_ENV]: "https://auth.example.test",
	}));
	assert.equal(parsed.ok, false);
	assert.equal(parsed.error.reason, "incomplete-slot");
});

test("rejects secondary origins when primary is missing", () => {
	const parsed = parsePrivateGatewayProfiles(env({
		[PRIVATE_GATEWAY_SECONDARY_AUTH_ORIGIN_ENV]: "https://secondary.example.test",
		[PRIVATE_GATEWAY_SECONDARY_GATEWAY_ORIGIN_ENV]: "https://secondary-gateway.example.test",
	}));
	assert.equal(parsed.ok, false);
	assert.equal(parsed.error.reason, "incomplete-slot");
});

test("rejects a non-https origin", () => {
	const parsed = parsePrivateGatewayProfiles(env({
		[PRIVATE_GATEWAY_PRIMARY_AUTH_ORIGIN_ENV]: "http://auth.example.test",
		[PRIVATE_GATEWAY_PRIMARY_GATEWAY_ORIGIN_ENV]: "https://gateway.example.test",
	}));
	assert.equal(parsed.ok, false);
	assert.equal(parsed.error.reason, "invalid-origin");
});
