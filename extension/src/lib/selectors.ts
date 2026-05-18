// Table of common selectors (first 4 bytes of calldata) so the popup
// can show the user "what" the dApp is calling.
// We don't decode the arguments (that would require a per-contract ABI),
// but recognising the function name already gives the user A LOT of
// context.
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

export function decodeSelector(dataHex: string): string | null {
  if (!dataHex || dataHex.length < 10) return null;
  const sel = dataHex.slice(0, 10).toLowerCase();
  return KNOWN[sel] ?? null;
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
