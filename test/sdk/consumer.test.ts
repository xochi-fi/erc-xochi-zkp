/**
 * Consumer SDK Integration Tests
 *
 * Validates the full integrator path for the Xochi ZKP system:
 *
 * Layer 1 (SDK): Load compiled circuit -> construct witness -> generate proof.
 *   No blockchain needed. Tests that a third-party developer can use
 *   @noir-lang/noir_js and @aztec/bb.js to produce valid proofs.
 *
 * Layer 2 (E2E): Deploy contracts to anvil -> verify proof on-chain ->
 *   submit to oracle -> read attestation. Full round-trip validation.
 *
 * Circuits with compiled artifacts: compliance, risk_score, membership, non_membership.
 * Circuits without artifacts (pending nargo build): pattern, attestation.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { createPublicClient, createWalletClient, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import {
  startAnvil,
  stopAnvil,
  ANVIL_RPC,
  ALICE_KEY,
  ALICE_ADDRESS,
} from "./anvil";
import {
  deployContracts,
  PROOF_TYPES,
  FIXTURE_HASHES,
  type DeployedContracts,
} from "./deploy";

// ============================================================
// Helpers
// ============================================================

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

function proofToHex(proof: Uint8Array): Hex {
  return `0x${Buffer.from(proof).toString("hex")}` as Hex;
}

function loadFixture(circuit: string): { proofHex: Hex; publicInputsHex: Hex } {
  const proof = readFileSync(
    resolve(REPO_ROOT, `test/fixtures/${circuit}/proof`),
  );
  const publicInputs = readFileSync(
    resolve(REPO_ROOT, `test/fixtures/${circuit}/public_inputs`),
  );
  return {
    proofHex: `0x${proof.toString("hex")}` as Hex,
    publicInputsHex: `0x${publicInputs.toString("hex")}` as Hex,
  };
}

/** Generate a proof using a shared Barretenberg instance. */
async function generateProof(
  circuitName: string,
  inputs: Record<string, unknown>,
  api: Barretenberg,
): Promise<{
  proofHex: Hex;
  publicInputsHex: Hex;
  publicInputs: string[];
}> {
  const circuit = loadCircuit(circuitName);
  const noir = new Noir(circuit);
  const backend = new UltraHonkBackend(circuit.bytecode, api);

  const { witness } = await noir.execute(normalizeInputs(inputs));
  const proofData = await backend.generateProof(witness, {
    verifierTarget: "evm",
  });

  return {
    proofHex: proofToHex(proofData.proof),
    publicInputsHex: encodePublicInputs(proofData.publicInputs),
    publicInputs: proofData.publicInputs,
  };
}

// ============================================================
// Standard test inputs
// ============================================================

const COMPLIANCE_INPUTS = {
  signals: [25, 0, 0, 0, 0, 0, 0, 0],
  weights: [100, 0, 0, 0, 0, 0, 0, 0],
  weight_sum: 100,
  provider_ids: ["1", "0", "0", "0", "0", "0", "0", "0"],
  num_providers: 1,
  jurisdiction_id: 0, // EU
  provider_set_hash: FIXTURE_HASHES.PROVIDER_SET_HASH,
  config_hash: FIXTURE_HASHES.CONFIG_HASH,
  timestamp: "1700000000",
  meets_threshold: true,
};

const RISK_SCORE_GT_INPUTS = {
  signals: [55, 0, 0, 0, 0, 0, 0, 0],
  weights: [100, 0, 0, 0, 0, 0, 0, 0],
  weight_sum: 100,
  proof_type: 1, // threshold
  direction: 1, // GT
  bound_lower: 4000,
  bound_upper: 0,
  result: true, // 55*100/100 = 5500 bps > 4000
  config_hash: FIXTURE_HASHES.CONFIG_HASH,
};

const MEMBERSHIP_INPUTS = {
  element: "42",
  merkle_index: "0",
  merkle_path: Array(20).fill("0"),
  merkle_root: "0",
  set_id: "1",
  timestamp: "1700000000",
  is_member: true,
};

const NON_MEMBERSHIP_INPUTS = {
  element: "50",
  low_leaf: "10",
  high_leaf: "100",
  low_index: "0",
  low_path: Array(20).fill("0"),
  high_index: "1",
  high_path: Array(20).fill("0"),
  merkle_root: "0",
  set_id: "1",
  timestamp: "1700000000",
  is_non_member: true,
};

// ============================================================
// Layer 1: SDK (no chain)
// ============================================================

describe("SDK layer (no chain)", () => {
  let api: Barretenberg;

  beforeAll(async () => {
    api = await Barretenberg.new();
  }, 120_000);

  afterAll(async () => {
    await api.destroy();
  });

  // ----------------------------------------------------------
  // Circuit loading
  // ----------------------------------------------------------

  describe("circuit loading", () => {
    it("loads compliance circuit artifact", () => {
      const circuit = loadCircuit("compliance");
      expect(circuit.bytecode).toBeDefined();
      expect(circuit.abi).toBeDefined();
      expect(circuit.abi.parameters.length).toBeGreaterThan(0);
    });

    it("loads risk_score circuit artifact", () => {
      const circuit = loadCircuit("risk_score");
      expect(circuit.bytecode).toBeDefined();
      expect(circuit.abi).toBeDefined();
    });

    it("loads membership circuit artifact", () => {
      const circuit = loadCircuit("membership");
      expect(circuit.bytecode).toBeDefined();
      expect(circuit.abi).toBeDefined();
    });

    it("loads non_membership circuit artifact", () => {
      const circuit = loadCircuit("non_membership");
      expect(circuit.bytecode).toBeDefined();
      expect(circuit.abi).toBeDefined();
    });

    it("throws on missing circuit artifact", () => {
      expect(() => loadCircuit("nonexistent")).toThrow();
    });
  });

  // ----------------------------------------------------------
  // Compliance proof generation
  // ----------------------------------------------------------

  describe("proof generation: compliance", () => {
    it("generates proof with single provider (EU)", async () => {
      const { proofHex, publicInputs } = await generateProof(
        "compliance",
        COMPLIANCE_INPUTS,
        api,
      );

      expect(proofHex.length).toBeGreaterThan(2);
      // 5 public inputs: jurisdiction_id, provider_set_hash, config_hash, timestamp, meets_threshold
      expect(publicInputs).toHaveLength(5);
    });

    it("generates proof for different jurisdiction (US)", async () => {
      const { publicInputs } = await generateProof(
        "compliance",
        { ...COMPLIANCE_INPUTS, jurisdiction_id: 1 },
        api,
      );
      expect(publicInputs).toHaveLength(5);
    });

    it("rejects when score exceeds threshold but meets_threshold=true", async () => {
      const circuit = loadCircuit("compliance");
      const noir = new Noir(circuit);

      // signal=90 -> score=9000 bps. EU threshold=7100. 9000 > 7100 -> non-compliant.
      const inputs = normalizeInputs({
        ...COMPLIANCE_INPUTS,
        signals: [90, 0, 0, 0, 0, 0, 0, 0],
        meets_threshold: true,
      });

      await expect(noir.execute(inputs)).rejects.toThrow();
    });

    it("rejects when num_providers is zero", async () => {
      const circuit = loadCircuit("compliance");
      const noir = new Noir(circuit);

      const inputs = normalizeInputs({
        ...COMPLIANCE_INPUTS,
        num_providers: 0,
      });

      await expect(noir.execute(inputs)).rejects.toThrow();
    });
  });

  // ----------------------------------------------------------
  // Risk score proof generation
  // ----------------------------------------------------------

  describe("proof generation: risk_score", () => {
    it("threshold proof: score > bound (GT)", async () => {
      const { publicInputs } = await generateProof(
        "risk_score",
        RISK_SCORE_GT_INPUTS,
        api,
      );
      // 6 public inputs: proof_type, direction, bound_lower, bound_upper, result, config_hash
      expect(publicInputs).toHaveLength(6);
    });

    it("threshold proof: score < bound (LT)", async () => {
      // score = 20*100/100 = 2000 bps < 5000
      const { publicInputs } = await generateProof(
        "risk_score",
        {
          ...RISK_SCORE_GT_INPUTS,
          signals: [20, 0, 0, 0, 0, 0, 0, 0],
          direction: 2, // LT
          bound_lower: 5000,
          result: true, // 2000 < 5000
        },
        api,
      );
      expect(publicInputs).toHaveLength(6);
    });

    it("range proof: score in [lower, upper]", async () => {
      // score = 55*100/100 = 5500 bps, range [4000, 7000]
      const { publicInputs } = await generateProof(
        "risk_score",
        {
          ...RISK_SCORE_GT_INPUTS,
          proof_type: 2, // range
          bound_lower: 4000,
          bound_upper: 7000,
          result: true, // 5500 in [4000, 7000]
        },
        api,
      );
      expect(publicInputs).toHaveLength(6);
    });

    it("rejects contradictory result", async () => {
      const circuit = loadCircuit("risk_score");
      const noir = new Noir(circuit);

      // score = 10*100/100 = 1000 bps. Claiming 1000 > 5000 = true is a lie.
      const inputs = normalizeInputs({
        ...RISK_SCORE_GT_INPUTS,
        signals: [10, 0, 0, 0, 0, 0, 0, 0],
        bound_lower: 5000,
        result: true,
      });

      await expect(noir.execute(inputs)).rejects.toThrow();
    });
  });

  // ----------------------------------------------------------
  // Membership proof generation
  // ----------------------------------------------------------

  describe("proof generation: membership", () => {
    it("accepts non-member witness (computed root != passed root)", async () => {
      const circuit = loadCircuit("membership");
      const noir = new Noir(circuit);

      // element=99 at index 0 with all-zero path. merkle_root=0.
      // Circuit computes root = H(H(99,1), 0) iterated 20x, which is not 0.
      // So computed_root != merkle_root -> membership_valid = false.
      // With is_member=false, the constraint (membership_valid == is_member) holds.
      const inputs = normalizeInputs({
        ...MEMBERSHIP_INPUTS,
        element: "99",
        is_member: false,
      });

      const { witness } = await noir.execute(inputs);
      expect(witness).toBeDefined();
    });

    it("rejects when is_member contradicts computation", async () => {
      const circuit = loadCircuit("membership");
      const noir = new Noir(circuit);

      // Same setup: computed_root != 0 -> not a member. Claiming is_member=true fails.
      const inputs = normalizeInputs({
        ...MEMBERSHIP_INPUTS,
        element: "99",
        is_member: true,
      });

      await expect(noir.execute(inputs)).rejects.toThrow();
    });
  });

  // ----------------------------------------------------------
  // Non-membership proof generation
  // ----------------------------------------------------------

  describe("proof generation: non_membership", () => {
    it("rejects invalid ordering (low > high)", async () => {
      const circuit = loadCircuit("non_membership");
      const noir = new Noir(circuit);

      const inputs = normalizeInputs({
        ...NON_MEMBERSHIP_INPUTS,
        low_leaf: "100",
        high_leaf: "10",
        is_non_member: true,
      });

      await expect(noir.execute(inputs)).rejects.toThrow();
    });

    it("rejects when element equals a leaf", async () => {
      const circuit = loadCircuit("non_membership");
      const noir = new Noir(circuit);

      const inputs = normalizeInputs({
        ...NON_MEMBERSHIP_INPUTS,
        element: "10",
        low_leaf: "10",
        high_leaf: "100",
        is_non_member: true,
      });

      await expect(noir.execute(inputs)).rejects.toThrow();
    });
  });

  // ----------------------------------------------------------
  // Pending circuits
  // ----------------------------------------------------------

  describe("proof generation: pattern", () => {
    it.todo("structuring analysis (awaiting nargo build)");
    it.todo("velocity analysis (awaiting nargo build)");
    it.todo("round amounts analysis (awaiting nargo build)");
  });

  describe("proof generation: attestation", () => {
    it.todo("valid credential proof (awaiting nargo build)");
    it.todo("expired credential rejection (awaiting nargo build)");
  });
});

// ============================================================
// Layer 2: E2E on-chain verification
// ============================================================

describe("E2E on-chain verification", () => {
  let contracts: DeployedContracts;
  let api: Barretenberg;

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
    api = await Barretenberg.new();
    await startAnvil();
    contracts = await deployContracts();
  }, 120_000);

  afterAll(async () => {
    await api.destroy();
    stopAnvil();
  });

  // ----------------------------------------------------------
  // Verifier contract
  // ----------------------------------------------------------

  describe("verifier contract", () => {
    it("verifies compliance proof on-chain", async () => {
      const { proofHex, publicInputsHex } = await generateProof(
        "compliance",
        COMPLIANCE_INPUTS,
        api,
      );

      const valid = await publicClient.readContract({
        address: contracts.verifier,
        abi: contracts.verifierAbi,
        functionName: "verifyProof",
        args: [PROOF_TYPES.COMPLIANCE, proofHex, publicInputsHex],
      });
      expect(valid).toBe(true);
    });

    it("verifies risk_score proof on-chain", async () => {
      const { proofHex, publicInputsHex } = await generateProof(
        "risk_score",
        RISK_SCORE_GT_INPUTS,
        api,
      );

      const valid = await publicClient.readContract({
        address: contracts.verifier,
        abi: contracts.verifierAbi,
        functionName: "verifyProof",
        args: [PROOF_TYPES.RISK_SCORE, proofHex, publicInputsHex],
      });
      expect(valid).toBe(true);
    });

    it("verifies membership proof from fixture", async () => {
      const { proofHex, publicInputsHex } = loadFixture("membership");

      const valid = await publicClient.readContract({
        address: contracts.verifier,
        abi: contracts.verifierAbi,
        functionName: "verifyProof",
        args: [PROOF_TYPES.MEMBERSHIP, proofHex, publicInputsHex],
      });
      expect(valid).toBe(true);
    });

    it("verifies non_membership proof from fixture", async () => {
      const { proofHex, publicInputsHex } = loadFixture("non_membership");

      const valid = await publicClient.readContract({
        address: contracts.verifier,
        abi: contracts.verifierAbi,
        functionName: "verifyProof",
        args: [PROOF_TYPES.NON_MEMBERSHIP, proofHex, publicInputsHex],
      });
      expect(valid).toBe(true);
    });

    it("rejects corrupted proof bytes", async () => {
      const { proofHex, publicInputsHex } = await generateProof(
        "risk_score",
        RISK_SCORE_GT_INPUTS,
        api,
      );

      // Flip a byte in the middle of the proof
      const corrupted = proofHex.slice(0, 100) + "ff" + proofHex.slice(102);

      await expect(
        publicClient.readContract({
          address: contracts.verifier,
          abi: contracts.verifierAbi,
          functionName: "verifyProof",
          args: [PROOF_TYPES.RISK_SCORE, corrupted as Hex, publicInputsHex],
        }),
      ).rejects.toThrow();
    });

    it("rejects proof routed to wrong proof type", async () => {
      const { proofHex, publicInputsHex } = await generateProof(
        "compliance",
        COMPLIANCE_INPUTS,
        api,
      );

      // Submit a compliance proof as if it were risk_score
      await expect(
        publicClient.readContract({
          address: contracts.verifier,
          abi: contracts.verifierAbi,
          functionName: "verifyProof",
          args: [PROOF_TYPES.RISK_SCORE, proofHex, publicInputsHex],
        }),
      ).rejects.toThrow();
    });
  });

  // ----------------------------------------------------------
  // Oracle submission
  // ----------------------------------------------------------

  describe("oracle submission", () => {
    it("submits compliance proof, attestation recorded", async () => {
      const { proofHex, publicInputsHex } = await generateProof(
        "compliance",
        COMPLIANCE_INPUTS,
        api,
      );

      const hash = await aliceClient.writeContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "submitCompliance",
        args: [
          0, // EU
          PROOF_TYPES.COMPLIANCE,
          proofHex,
          publicInputsHex,
          FIXTURE_HASHES.PROVIDER_SET_HASH,
        ],
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).toBe("success");
    });

    it("checkCompliance returns true after submission", async () => {
      const [valid] = (await publicClient.readContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "checkCompliance",
        args: [ALICE_ADDRESS, 0],
      })) as [boolean, unknown];
      expect(valid).toBe(true);
    });

    it("rejects duplicate proof (replay protection)", async () => {
      const { proofHex, publicInputsHex } = await generateProof(
        "compliance",
        COMPLIANCE_INPUTS,
        api,
      );

      // First submission
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
      await publicClient.waitForTransactionReceipt({ hash });

      // Same proof again should revert
      await expect(
        aliceClient.writeContract({
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
        }),
      ).rejects.toThrow();
    });

    it("submits for different jurisdiction (US)", async () => {
      const { proofHex, publicInputsHex } = await generateProof(
        "compliance",
        { ...COMPLIANCE_INPUTS, jurisdiction_id: 1 },
        api,
      );

      const hash = await aliceClient.writeContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "submitCompliance",
        args: [
          1, // US
          PROOF_TYPES.COMPLIANCE,
          proofHex,
          publicInputsHex,
          FIXTURE_HASHES.PROVIDER_SET_HASH,
        ],
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      expect(receipt.status).toBe("success");

      const [valid] = (await publicClient.readContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "checkCompliance",
        args: [ALICE_ADDRESS, 1],
      })) as [boolean, unknown];
      expect(valid).toBe(true);
    });
  });

  // ----------------------------------------------------------
  // Pending circuits
  // ----------------------------------------------------------

  describe("pattern/attestation (pending circuits)", () => {
    it.todo("verify pattern proof on-chain (awaiting nargo build)");
    it.todo("verify attestation proof on-chain (awaiting nargo build)");
  });
});
