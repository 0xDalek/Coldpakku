// Minimal WebSerial API type declarations. @types/web-serial-api exists
// but the spec is already shipped in recent TS lib targets (just not in
// the default lib.dom of TS 5.x). We declare the bits we actually use.

interface SerialPort {
  readonly readable: ReadableStream<Uint8Array> | null;
  readonly writable: WritableStream<Uint8Array> | null;
  open(options: SerialOptions): Promise<void>;
  close(): Promise<void>;
  forget?(): Promise<void>;
  getInfo(): { usbVendorId?: number; usbProductId?: number };
}

interface SerialOptions {
  baudRate: number;
  dataBits?: 7 | 8;
  stopBits?: 1 | 2;
  parity?: "none" | "even" | "odd";
  bufferSize?: number;
  flowControl?: "none" | "hardware";
}

interface SerialPortFilter {
  usbVendorId?: number;
  usbProductId?: number;
}

interface SerialPortRequestOptions {
  filters?: SerialPortFilter[];
  allowedBluetoothServiceClassIds?: any[];
}

interface Serial extends EventTarget {
  getPorts(): Promise<SerialPort[]>;
  requestPort(options?: SerialPortRequestOptions): Promise<SerialPort>;
}

interface Navigator {
  readonly serial: Serial;
}

interface WorkerNavigator {
  readonly serial: Serial;
}
