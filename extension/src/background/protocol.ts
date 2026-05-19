// Constants and helpers for the GBA handshake protocol (v4).
// Mirrors [src/link/protocol.h] and [pc/protocol.py].

export const PROTO_READY         = 0xaa;
export const PROTO_ACK           = 0xbb;
export const PROTO_TX_RLP        = 0xcd;
export const PROTO_DONE          = 0xcc;
export const PROTO_SIGSTART      = 0xce;
export const PROTO_TXRESULT      = 0xcf;
export const PROTO_CANCEL        = 0xff;

export const PROTO_GET_ADDRESS   = 0xc0;
export const PROTO_ADDRSTART     = 0xc1;
export const PROTO_PERSONAL_SIGN = 0xd0;
export const PROTO_TYPED_DATA    = 0xd1;

// v5: chain lock policy. See src/link/protocol.h
export const PROTO_GET_POLICY    = 0xc2;
export const PROTO_POLICYSTART   = 0xc3;
export const PROTO_REJECT_CHAIN  = 0xfd;

// v6: tx + informational metadata (origin, contract name, token info)
export const PROTO_TX_RLP_META   = 0xd2;

// v7: heartbeat. The extension sends one every ~30s; the GBA only uses
// it to refresh the 'link:' indicator on AWAITING TRANSACTION.
export const PROTO_HEARTBEAT     = 0xc4;

// v8: connect approval. The extension sends it the first time a dApp
// calls eth_requestAccounts. The GBA shows the origin and asks A/B.
export const PROTO_CONNECT_REQUEST = 0xc5;
export const PROTO_CONNECT_OK      = 0xc6;

// TLV types inside the meta block. Mirrors src/link/protocol.h.
export const META_TYPE_ORIGIN      = 0x01;
export const META_TYPE_TO_NAME     = 0x02;
export const META_TYPE_TO_SYMBOL   = 0x03;
export const META_TYPE_TO_DECIMALS = 0x04;

export const META_ORIGIN_MAX  = 96;
export const META_NAME_MAX    = 32;
export const META_SYMBOL_MAX  = 16;
export const PROTO_TX_META_MAX = 256;

export const PROTO_TX_RLP_MAX        = 4096;
export const PROTO_PERSONAL_MSG_MAX  = 4096;
export const PROTO_TYPED_TEXT_MAX    = 4096;
// v7: optional EIP-712 TLV tree appended to PROTO_TYPED_DATA so the GBA
// can verify the hashes on-device when the user requests it (L+R combo).
// tree_len = 0 keeps the legacy blind-only flow.
export const PROTO_TYPED_TREE_MAX    = 8192;

export const TXRESULT_BROADCAST_OK   = 0x00;
export const TXRESULT_BROADCAST_ERR  = 0x01;
export const TXRESULT_NO_BROADCAST   = 0x02;
export const TXRESULT_ERRMSG_MAX     = 64;

export const SIG_V_SENTINEL = 0xfe;
