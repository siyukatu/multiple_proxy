import { deadline } from "https://deno.land/std/async/mod.ts";

function ipAddrToBytes(ip: string): Uint8Array {
  return new Uint8Array(ip.split('.').map(Number));
}

function generatePacket(protocol: string, target: [string, number]): Uint8Array {
  const encoder = new TextEncoder();

  switch (protocol) {
    case "socks5":
      return new Uint8Array([
        0x05,
        0x01,
        0x00,
        0x03,
        target[0].length,
        ...encoder.encode(target[0]),
        (target[1] >> 8) & 0xff,
        target[1] & 0xff,
      ]);
    case "socks4":
      return new Uint8Array([
        0x04,
        0x01,
        (target[1] >> 8) & 0xff,
        target[1] & 0xff,
        ...ipAddrToBytes(target[0]),
        0x00,
      ]);
    case "http":
      const request = `CONNECT ${target[0]}:${target[1]} HTTP/1.1\r\nHost: ${target[0]}:${target[1]}\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n`;
      return encoder.encode(request);
    default:
      throw new Error(`Unsupported protocol for generating packet: ${protocol}`);
  }
}

function checkResponse(protocol: string, data: Uint8Array): boolean {
  const decoder = new TextDecoder();

  switch (protocol) {
    case "socks5":
      return data.length >= 2 && data[0] === 0x05 && data[1] === 0x00;
    case "socks4":
      return data.length >= 2 && data[0] === 0x00 && data[1] === 0x5a;
    case "http":
      const response = decoder.decode(data);
      return response.split("\r\n")[0].toLowerCase().includes("200 connection established");
    default:
      return false;
  }
}

function parseProxy(proxy: string): [string, string, number] {
  const [protocol, address] = proxy.split("://");
  const [host, port] = address.split(":");
  return [protocol, host, port ? parseInt(port) : 1080];
}

async function proxySocket(proxies: string[], target: [string, number], timeout = 10000): Promise<Deno.Conn> {
  if (proxies.length === 0) {
    throw new Error("Proxy list cannot be empty.");
  }

  let conn: Deno.Conn | null = null;
  const firstProxyInfo = parseProxy(proxies[0]);
  let currentProtocolForHandshake = firstProxyInfo[0];

  try {
    conn = await deadline(Deno.connect({ hostname: firstProxyInfo[1], port: firstProxyInfo[2] }), timeout);

    const hops: Array<[string, number, string?]> = [];
    for (let i = 1; i < proxies.length; i++) {
      const nextProxyInfo = parseProxy(proxies[i]);
      hops.push([nextProxyInfo[1], nextProxyInfo[2], nextProxyInfo[0]]);
    }
    hops.push([target[0], target[1], undefined]);

    for (const hop of hops) {
      const [hostForNextHop, portForNextHop, protocolOfNextProxy] = hop;

      const packet = generatePacket(currentProtocolForHandshake, [hostForNextHop, portForNextHop]);
      await deadline(conn.write(packet), timeout);

      const responseBuffer = new Uint8Array(1024);
      const bytesRead = await deadline(conn.read(responseBuffer), timeout);

      if (bytesRead === null) {
        throw new Error(`Connection closed prematurely by ${currentProtocolForHandshake} proxy while trying to reach ${hostForNextHop}:${portForNextHop}.`);
      }

      if (!checkResponse(currentProtocolForHandshake, responseBuffer.subarray(0, bytesRead))) {
        throw new Error(`Handshake failed with ${currentProtocolForHandshake} proxy for ${hostForNextHop}:${portForNextHop}. Invalid response.`);
      }
      
      if (protocolOfNextProxy) {
        currentProtocolForHandshake = protocolOfNextProxy;
      }
    }
    
    if (!conn) {
        throw new Error("Connection object is null after successful proxy chain.");
    }
    return conn;

  } catch (e) {
    if (conn) {
      try {
        conn.close();
      } catch (closeError) {
      }
    }
    const errorMessage = e instanceof Error ? e.message : String(e);
    throw new Error(`Proxy socket setup failed: ${errorMessage}`);
  }
}

export { proxySocket };
