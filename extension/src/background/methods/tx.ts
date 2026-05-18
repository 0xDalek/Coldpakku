// Handlers for eth_sendTransaction and eth_signTransaction.
//
// Flow:
//   1) buildTx: nonce/gas/fees (public RPC) -> unsigned RLP + signing hash
//   2) buildConfirmRequest: builds the payload the user sees in popup + GBA
//   3) buildTxMetaForGba: TLV with origin + symbol/decimals (anti-phishing)
//   4) session.signTx -> signature from the GBA
//   5) assemble signed tx + optional broadcast (sendTx) / return raw (signTx)

import type { Address, Hex, NetworkInfo, TxRequest } from "../../lib/types";
import { normalizeAddress, toChecksumAddress } from "../../lib/address";
import { keccak256, bytesToHex, hexToBytes } from "../../lib/keccak";
import {
  encodeEip1559,
  encodeEip1559Signed,
  encodeLegacyForSigning,
  encodeLegacySigned,
} from "../../lib/rlp";
import { rpcCall, RpcError } from "../rpc-passthrough";
import { withGbaSession } from "../serial-bridge";
import { recoverRecid } from "../sig-recover";
import {
  startActiveRequest,
  clearActiveRequest,
  type ConfirmRequest,
} from "../confirm-orchestrator";
import {
  META_ORIGIN_MAX,
  TXRESULT_BROADCAST_ERR,
  TXRESULT_BROADCAST_OK,
  TXRESULT_NO_BROADCAST,
} from "../protocol";
import { getActiveNetwork, setGbaPolicyChainId } from "../session";
import { decodeSelector, shortFuncName } from "../../lib/selectors";
import { encodeTxMetaTlv, type TxMeta } from "../../lib/tx_meta";
import { assertConnected, mustAddressBytes, parseHexBigInt } from "./_shared";

interface BuiltTx {
  rlp: Uint8Array;
  signedAssemble: (yParity: 0 | 1, r: Uint8Array, s: Uint8Array) => Uint8Array;
  signingHash: Uint8Array;
  to: Address | null;
  valueHex: Hex;
  chainId: number;
  isLegacy: boolean;
  // extra metadata for the confirm popup
  nonce: bigint;
  gas: bigint;
  data: Uint8Array;
  maxFee?: bigint;
  tip?: bigint;
  gasPrice?: bigint;
}

async function buildTx(req: TxRequest): Promise<BuiltTx> {
  const net = await getActiveNetwork();
  const fromAddr = await mustAddressBytes();
  const fromHex = ("0x" + bytesToHex(fromAddr)) as Hex;

  // nonce
  let nonce = req.nonce !== undefined ? parseHexBigInt(req.nonce) : undefined;
  if (nonce === undefined) {
    const n = (await rpcCall(net, "eth_getTransactionCount", [fromHex, "pending"])) as Hex;
    nonce = parseHexBigInt(n);
  }
  // gas estimation
  const data = req.data ? hexToBytes(req.data) : new Uint8Array(0);
  const value = req.value !== undefined ? parseHexBigInt(req.value) : 0n;
  const to = req.to ? normalizeAddress(req.to) : null;

  let gas: bigint;
  if (req.gas !== undefined) {
    gas = parseHexBigInt(req.gas);
  } else {
    try {
      const g = (await rpcCall(net, "eth_estimateGas", [
        {
          from: fromHex,
          to: to ?? undefined,
          value: ("0x" + value.toString(16)) as Hex,
          data: req.data ?? "0x",
        },
      ])) as Hex;
      gas = (parseHexBigInt(g) * 120n) / 100n;   // +20% margin
    } catch {
      gas = 100000n;
    }
  }

  // If the user explicitly passes gasPrice (and not maxFeePerGas), use legacy.
  const isLegacy = req.gasPrice !== undefined && req.maxFeePerGas === undefined;

  if (isLegacy) {
    const gasPrice = req.gasPrice ? parseHexBigInt(req.gasPrice) : await getGasPrice(net);
    const tx = {
      type: 0 as const,
      chainId: net.chainId,
      nonce: Number(nonce),
      gasPrice,
      gas,
      to,
      value,
      data,
    };
    const rlp = encodeLegacyForSigning(tx);
    const signingHash = keccak256(rlp);
    const signedAssemble = (yParity: 0 | 1, r: Uint8Array, s: Uint8Array) =>
      encodeLegacySigned(tx, yParity, r, s);
    return {
      rlp, signedAssemble, signingHash, to, isLegacy: true,
      valueHex: ("0x" + value.toString(16)) as Hex, chainId: net.chainId,
      nonce, gas, data, gasPrice,
    };
  }

  // EIP-1559: figure out maxFee/tip if not provided
  const maxFee = req.maxFeePerGas
    ? parseHexBigInt(req.maxFeePerGas)
    : await getMaxFee(net);
  const tip = req.maxPriorityFeePerGas
    ? parseHexBigInt(req.maxPriorityFeePerGas)
    : await getTip(net);

  const tx = {
    type: 2 as const,
    chainId: net.chainId,
    nonce: Number(nonce),
    maxPriorityFeePerGas: tip,
    maxFeePerGas: maxFee,
    gas,
    to,
    value,
    data,
    accessList: [],
  };
  const envelope = encodeEip1559(tx);   // 0x02 || rlp(...)
  const signingHash = keccak256(envelope);
  const signedAssemble = (yParity: 0 | 1, r: Uint8Array, s: Uint8Array) =>
    encodeEip1559Signed(tx, yParity, r, s);
  return {
    rlp: envelope, signedAssemble, signingHash, to, isLegacy: false,
    valueHex: ("0x" + value.toString(16)) as Hex, chainId: net.chainId,
    nonce, gas, data, maxFee, tip,
  };
}

async function buildConfirmRequest(
  kind: "send_tx" | "sign_tx",
  origin: string,
  address: Address,
  raw: TxRequest,
  built: BuiltTx,
): Promise<ConfirmRequest> {
  const net = await getActiveNetwork();
  const dataHex = (raw.data ?? "0x") as Hex;
  const decodedFunc = decodeSelector(dataHex);
  const decodedSummary = decodedFunc ? `Calls ${shortFuncName(dataHex)}` : null;
  const cReq: ConfirmRequest = {
    kind,
    origin,
    address,
    chainId: built.chainId,
    chainName: net.name,
    nativeSymbol: net.nativeCurrency.symbol,
    to: built.to,
    valueHex: built.valueHex,
    dataLen: built.data.length,
    dataHex,
    decodedFunc,
    decodedSummary,
    signingHashHex: ("0x" + bytesToHex(built.signingHash)) as Hex,
    nonceHex: ("0x" + built.nonce.toString(16)) as Hex,
    gasHex: ("0x" + built.gas.toString(16)) as Hex,
  };
  if (built.isLegacy && built.gasPrice !== undefined) {
    cReq.gasPriceHex = ("0x" + built.gasPrice.toString(16)) as Hex;
  } else {
    if (built.maxFee !== undefined) cReq.maxFeeHex = ("0x" + built.maxFee.toString(16)) as Hex;
    if (built.tip !== undefined) cReq.tipHex = ("0x" + built.tip.toString(16)) as Hex;
  }
  return cReq;
}

// ---------------------------------------------------------------------------
// Tx metadata TLV for the GBA (origin + ERC-20 symbol/decimals)
// ---------------------------------------------------------------------------

async function ethCallView(
  net: NetworkInfo,
  to: Hex,
  selector: string,
): Promise<Uint8Array | null> {
  try {
    const result = (await rpcCall(net, "eth_call", [
      { to, data: selector },
      "latest",
    ])) as Hex;
    return hexToBytes(result);
  } catch {
    return null;
  }
}

/** Decodes an ABI string. Supports dynamic strings (modern ERC-20) and
 *  fixed bytes32 (legacy DAI). Returns null if it doesn't fit either. */
function decodeAbiString(data: Uint8Array): string | null {
  if (data.length === 0) return null;
  if (data.length === 32) {
    let end = 32;
    for (let i = 0; i < 32; i++) {
      if (data[i] === 0) { end = i; break; }
    }
    if (end === 0) return null;
    return new TextDecoder("ascii").decode(data.slice(0, end));
  }
  if (data.length < 64) return null;
  const len = ((data[60] << 24) | (data[61] << 16) | (data[62] << 8) | data[63]) >>> 0;
  if (len === 0 || len > data.length - 64) return null;
  return new TextDecoder("ascii").decode(data.slice(64, 64 + len));
}

function decodeAbiUint8(data: Uint8Array): number | null {
  if (data.length !== 32) return null;
  for (let i = 0; i < 31; i++) if (data[i] !== 0) return null;
  return data[31];
}

const SEL_SYMBOL   = "0x95d89b41";
const SEL_DECIMALS = "0x313ce567";

async function queryErc20Info(
  net: NetworkInfo,
  to: Hex,
): Promise<{ symbol?: string; decimals?: number }> {
  const result: { symbol?: string; decimals?: number } = {};
  const [symBytes, decBytes] = await Promise.all([
    ethCallView(net, to, SEL_SYMBOL),
    ethCallView(net, to, SEL_DECIMALS),
  ]);
  if (symBytes) {
    const s = decodeAbiString(symBytes);
    if (s && s.length > 0 && s.length <= 16) result.symbol = s;
  }
  if (decBytes) {
    const d = decodeAbiUint8(decBytes);
    if (d !== null && d <= 77) result.decimals = d;
  }
  return result;
}

function cleanOrigin(origin: string): string {
  return origin.replace(/^https?:\/\//i, "").slice(0, META_ORIGIN_MAX);
}

async function buildTxMetaForGba(
  origin: string,
  net: NetworkInfo,
  built: BuiltTx,
): Promise<Uint8Array | undefined> {
  const m: TxMeta = { origin: cleanOrigin(origin) };
  if (built.to && built.data.length >= 4) {
    try {
      const info = await queryErc20Info(net, built.to);
      if (info.symbol !== undefined)   m.toSymbol = info.symbol;
      if (info.decimals !== undefined) m.toDecimals = info.decimals;
    } catch {
      // Best-effort: if the RPC fails, send only the origin.
    }
  }
  try {
    return encodeTxMetaTlv(m);
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Fee oracles
// ---------------------------------------------------------------------------

async function getGasPrice(net: NetworkInfo): Promise<bigint> {
  const g = (await rpcCall(net, "eth_gasPrice", [])) as Hex;
  return parseHexBigInt(g);
}

async function getMaxFee(net: NetworkInfo): Promise<bigint> {
  // baseFee from the latest block + default tip + margin
  const block = (await rpcCall(net, "eth_getBlockByNumber", ["latest", false])) as any;
  const base = block?.baseFeePerGas ? parseHexBigInt(block.baseFeePerGas) : 0n;
  const tip = await getTip(net);
  return base * 2n + tip;
}

async function getTip(net: NetworkInfo): Promise<bigint> {
  try {
    const t = (await rpcCall(net, "eth_maxPriorityFeePerGas", [])) as Hex;
    return parseHexBigInt(t);
  } catch {
    return 1500000000n;   // 1.5 gwei default
  }
}

// ---------------------------------------------------------------------------
// Handlers exposed to the dispatcher
// ---------------------------------------------------------------------------

export async function ethSendTransaction(origin: string, raw: TxRequest): Promise<Hex> {
  await assertConnected(origin);
  const built = await buildTx(raw);
  const addrBytes = await mustAddressBytes();
  const checksum = toChecksumAddress(addrBytes);

  const cReq: ConfirmRequest = await buildConfirmRequest(
    "send_tx", origin, checksum, raw, built,
  );
  const { cancelled } = startActiveRequest(cReq);
  try {
    return await withGbaSession(async (session) => {
      const net = await getActiveNetwork();
      const metaBytes = await buildTxMetaForGba(origin, net, built);
      const out = await session.signTx(built.rlp, metaBytes);
      if (cancelled.cancelled) {
        throw new RpcError(4001, "User cancelled in extension popup.");
      }
      if (out.kind === "reject_chain") {
        await setGbaPolicyChainId(out.expected).catch(() => {});
        throw new RpcError(
          4901,
          `GBA is locked to chainId ${out.expected}. ` +
            `This transaction was for chainId ${out.got}. ` +
            `Switch the network in the dApp, or use L/R on the GBA to change the chain lock.`,
          { expected: out.expected, got: out.got },
        );
      }
      if (out.kind === "cancel") {
        throw new RpcError(4001, "User rejected on GBA (button B).");
      }
      const sig = out.sig;
      const { r, s, yParity } = recoverRecid(built.signingHash, sig, addrBytes);
      const rawSigned = built.signedAssemble(yParity, r, s);
      const rawHex = ("0x" + bytesToHex(rawSigned)) as Hex;

      let txhash: Hex;
      try {
        txhash = (await rpcCall(net, "eth_sendRawTransaction", [rawHex])) as Hex;
        await session
          .sendTxResult(TXRESULT_BROADCAST_OK, hexToBytes(txhash))
          .catch(() => {});
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        await session
          .sendTxResult(TXRESULT_BROADCAST_ERR, undefined, msg)
          .catch(() => {});
        throw new RpcError(-32000, `broadcast failed: ${msg}`);
      }
      return txhash;
    });
  } finally {
    clearActiveRequest();
  }
}

export async function ethSignTransaction(origin: string, raw: TxRequest): Promise<Hex> {
  await assertConnected(origin);
  const built = await buildTx(raw);
  const addrBytes = await mustAddressBytes();
  const checksum = toChecksumAddress(addrBytes);

  const cReq: ConfirmRequest = await buildConfirmRequest(
    "sign_tx", origin, checksum, raw, built,
  );
  const { cancelled } = startActiveRequest(cReq);
  try {
    return await withGbaSession(async (session) => {
      const net = await getActiveNetwork();
      const metaBytes = await buildTxMetaForGba(origin, net, built);
      const out = await session.signTx(built.rlp, metaBytes);
      if (cancelled.cancelled) {
        throw new RpcError(4001, "User cancelled in extension popup.");
      }
      if (out.kind === "reject_chain") {
        await setGbaPolicyChainId(out.expected).catch(() => {});
        throw new RpcError(
          4901,
          `GBA is locked to chainId ${out.expected}. ` +
            `This transaction was for chainId ${out.got}. ` +
            `Switch the network in the dApp, or use L/R on the GBA to change the chain lock.`,
          { expected: out.expected, got: out.got },
        );
      }
      if (out.kind === "cancel") {
        throw new RpcError(4001, "User rejected on GBA (button B).");
      }
      const sig = out.sig;
      const { r, s, yParity } = recoverRecid(built.signingHash, sig, addrBytes);
      const rawSigned = built.signedAssemble(yParity, r, s);
      await session
        .sendTxResult(TXRESULT_NO_BROADCAST, keccak256(rawSigned))
        .catch(() => {});
      return ("0x" + bytesToHex(rawSigned)) as Hex;
    });
  } finally {
    clearActiveRequest();
  }
}
