/**
 * Consumer SDK test
 *
 * Validates the integrator path: load circuit -> generate proof ->
 * deploy contracts -> verify on-chain. This is what a third-party
 * developer would do to use the Xochi ZKP system from TypeScript.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { createPublicClient, createWalletClient, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { startAnvil, stopAnvil, ANVIL_RPC, ALICE_KEY, ALICE_ADDRESS } from "./anvil";
import {
  deployContracts,
  PROOF_TYPES,
  FIXTURE_HASHES,
  type DeployedContracts,
} from "./deploy";

const REPO_ROOT = resolve(import.meta.dirname, "../..");

function loadCircuit(name: string) {
  const path = resolve(REPO_ROOT, `circuits/${name}/target/${name}.json`);
  return JSON.parse(readFileSync(path, "utf-8"));
}

function normalizeInputs(
  inputs: Record<string, unknown>,
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(inputs)) {
    if (Array.isArray(value)) {
      result[key] = value.map(String);
    } else if (typeof value === "boolean") {
      result[key] = value ? "1" : "0";
    } else {
      result[key] = String(value);
    }
  }
  return result;
}

function encodePublicInputs(inputs: string[]): Hex {
  const encoded = inputs
    .map((input) => {
      const hex = input.startsWith("0x") ? input.slice(2) : input;
      return hex.padStart(64, "0");
    })
    .join("");
  return `0x${encoded}` as Hex;
}

// ============================================================
// Test setup
// ============================================================

let contracts: DeployedContracts;

const alice = privateKeyToAccount(ALICE_KEY);
const publicClient = createPublicClient({
  chain: foundry,
  transport: http(ANVIL_RPC),
});
const aliceClient = createWalletClient({
  account: alice,
  chain: foundry,
  transport: http(ANVIL_RPC),
});

beforeAll(async () => {
  await startAnvil();
  contracts = await deployContracts();
}, 120_000);

afterAll(() => {
  stopAnvil();
});

// ============================================================
// Tests
// ============================================================

describe("consumer SDK flow", () => {
  it("loads a circuit and generates a risk_score proof", async () => {
    const circuit = loadCircuit("risk_score");
    expect(circuit.bytecode).toBeDefined();
    expect(circuit.abi).toBeDefined();

    const api = await Barretenberg.new();
    const noir = new Noir(circuit);
    const backend = new UltraHonkBackend(circuit.bytecode, api);

    try {
      const inputs = normalizeInputs({
        signals: [55, 0, 0, 0, 0, 0, 0, 0],
        weights: [100, 0, 0, 0, 0, 0, 0, 0],
        weight_sum: 100,
        proof_type: 1,
        direction: 1,
        bound_lower: 4000,
        bound_upper: 0,
        result: true,
        config_hash: FIXTURE_HASHES.CONFIG_HASH,
      });

      const { witness } = await noir.execute(inputs);
      const proofData = await backend.generateProof(witness, {
        verifierTarget: "evm",
      });

      expect(proofData.proof).toBeInstanceOf(Uint8Array);
      expect(proofData.proof.length).toBeGreaterThan(0);
      expect(proofData.publicInputs).toHaveLength(6);

      // Verify on-chain
      const proofHex =
        `0x${Buffer.from(proofData.proof).toString("hex")}` as Hex;
      const publicInputsHex = encodePublicInputs(proofData.publicInputs);

      const valid = await publicClient.readContract({
        address: contracts.verifier,
        abi: contracts.verifierAbi,
        functionName: "verifyProof",
        args: [PROOF_TYPES.RISK_SCORE, proofHex, publicInputsHex],
      });
      expect(valid).toBe(true);
    } finally {
      await api.destroy();
    }
  });

  it("generates a compliance proof and submits to oracle", async () => {
    const circuit = loadCircuit("compliance");

    const api = await Barretenberg.new();
    const noir = new Noir(circuit);
    const backend = new UltraHonkBackend(circuit.bytecode, api);

    try {
      const inputs = normalizeInputs({
        signals: [25, 0, 0, 0, 0, 0, 0, 0],
        weights: [100, 0, 0, 0, 0, 0, 0, 0],
        weight_sum: 100,
        provider_ids: ["1", "0", "0", "0", "0", "0", "0", "0"],
        num_providers: 1,
        jurisdiction_id: 0,
        provider_set_hash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        config_hash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        meets_threshold: true,
      });

      const { witness } = await noir.execute(inputs);
      const proofData = await backend.generateProof(witness, {
        verifierTarget: "evm",
      });

      const proofHex =
        `0x${Buffer.from(proofData.proof).toString("hex")}` as Hex;
      const publicInputsHex = encodePublicInputs(proofData.publicInputs);

      // Submit to oracle
      const hash = await aliceClient.writeContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "submitCompliance",
        args: [
          0,
          PROOF_TYPES.COMPLIANCE,
          proofHex,
          publicInputsHex,
          FIXTURE_HASHES.PROVIDER_SET_HASH,
        ],
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).toBe("success");

      // Verify attestation recorded
      const [valid] = (await publicClient.readContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "checkCompliance",
        args: [ALICE_ADDRESS, 0],
      })) as [boolean, unknown];
      expect(valid).toBe(true);
    } finally {
      await api.destroy();
    }
  });

  it("rejects proofs where result contradicts computation", async () => {
    const circuit = loadCircuit("risk_score");
    const noir = new Noir(circuit);

    // score = 10, threshold = 5000 bps. 10*100/100 = 1000 < 5000.
    // Setting result=true should cause circuit constraint failure.
    const inputs = normalizeInputs({
      signals: [10, 0, 0, 0, 0, 0, 0, 0],
      weights: [100, 0, 0, 0, 0, 0, 0, 0],
      weight_sum: 100,
      proof_type: 1,
      direction: 1,
      bound_lower: 5000,
      bound_upper: 0,
      result: true,
      config_hash: FIXTURE_HASHES.CONFIG_HASH,
    });

    await expect(noir.execute(inputs)).rejects.toThrow();
  });
});
