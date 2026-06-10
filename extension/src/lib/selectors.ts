// Table of common selectors (first 4 bytes of calldata) for the
// popup's quick "what is the dApp calling?" hint.
//
// SINCE v0.3 THIS TABLE IS PURELY INFORMATIONAL FOR THE POPUP. The
// authoritative selector table lives on-device at
// `src/crypto/abi_selectors.c` and the GBA does its own ABI decoding,
// so the popup cannot mislabel a "transfer()" as an "approve()" —
// the firmware will catch a mismatch. The popup table is kept here
// only so the user sees the function name BEFORE confirming on the
// cartridge, and so the icon/colouring per call type works without
// waiting on the serial roundtrip.
//
// The `firmwareDecoded` map below mirrors which selectors are also
// recognised on-device (used by the popup to show a small
// "decoded on cartridge" badge next to the function name).
//
// Selectors generated with keccak256(signature)[0:4] and verified via
// 4byte.directory for the most common ones.

const KNOWN: Record<string, string> = {
  // ERC-20
  "0xa9059cbb": "transfer(address,uint256)",
  "0x095ea7b3": "approve(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
  "0x40c10f19": "mint(address,uint256)",
  "0x42966c68": "burn(uint256)",

  // ERC-721
  "0x42842e0e": "safeTransferFrom(address,address,uint256)",
  "0xb88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
  "0xa22cb465": "setApprovalForAll(address,bool)",

  // Uniswap V2 router
  "0x7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
  "0x18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
  "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
  "0x4a25d94a": "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
  "0xfb3bdb41": "swapETHForExactTokens(uint256,address[],address,uint256)",
  "0x8803dbee": "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
  "0xf305d719": "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
  "0xe8e33700": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
  "0xbaa2abde": "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
  "0x02751cec": "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",

  // Uniswap V3 / PancakeSwap V3
  "0x5ae401dc": "multicall(uint256,bytes[])",
  "0xac9650d8": "multicall(bytes[])",
  "0x414bf389": "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
  "0xc04b8d59": "exactInput((bytes,address,uint256,uint256,uint256))",
  "0xdb3e2198": "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
  "0xf28c0498": "exactOutput((bytes,address,uint256,uint256,uint256))",
  "0x88316456": "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
  "0x0c49ccbe": "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "0x219f5d17": "increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))",

  // WETH / WBNB
  "0xd0e30db0": "deposit()",
  "0x2e1a7d4d": "withdraw(uint256)",

  // Generic multicall
  "0x252dba42": "aggregate((address,bytes)[])",

  // Permit ERC-2612
  "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
};

// Mirror of src/crypto/abi_selectors.c — selectors the GBA can also
// decode on-device. Keep both lists in sync when adding selectors to
// the firmware (otherwise the popup badge will lie).
const FIRMWARE_DECODED: ReadonlySet<string> = new Set([
  // ERC-20
  "0xa9059cbb", "0x095ea7b3", "0x23b872dd", "0x40c10f19", "0x42966c68",
  // ERC-721 / ERC-1155
  "0x42842e0e", "0xb88d4fde", "0xa22cb465",
  // WETH
  "0xd0e30db0", "0x2e1a7d4d",
  // ERC-2612 Permit
  "0xd505accf",
  // Uniswap V2 router
  "0x7ff36ab5", "0x18cbafe5", "0x38ed1739", "0x4a25d94a",
  "0xfb3bdb41", "0x8803dbee",
  "0xf305d719", "0xe8e33700", "0xbaa2abde", "0x02751cec",
  // multicall + Universal Router (top-level only; inner sub-cmds
  // are NOT decoded on-device in v0.3)
  "0xac9650d8", "0x5ae401dc", "0x3593564c", "0x24856bc3",
]);

export function decodeSelector(dataHex: string): string | null {
  if (!dataHex || dataHex.length < 10) return null;
  const sel = dataHex.slice(0, 10).toLowerCase();
  return KNOWN[sel] ?? null;
}

/** True iff the cartridge ROM (v0.3+) also knows how to decode this
 *  selector at the ABI level. Pure informational; the popup uses it
 *  to render a "verified on cartridge" badge so the user knows the
 *  rendered function name will be the SAME on-device. */
export function isFirmwareDecoded(dataHex: string): boolean {
  if (!dataHex || dataHex.length < 10) return false;
  return FIRMWARE_DECODED.has(dataHex.slice(0, 10).toLowerCase());
}

/** Returns the plain function name (without types), e.g. "transfer" for
 *  "transfer(address,uint256)". If there is no match, returns
 *  "call <selector>" as a short fallback. */
export function shortFuncName(dataHex: string): string {
  if (!dataHex || dataHex.length < 10) return "(empty data)";
  const sel = dataHex.slice(0, 10).toLowerCase();
  const sig = KNOWN[sel];
  if (!sig) return `unknown call ${sel}`;
  const m = sig.match(/^([^(]+)\(/);
  return m ? m[1] : sig;
}
