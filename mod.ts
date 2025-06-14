import { deadline } from "jsr:@std/async@1";

/**
 * IPアドレス文字列をバイト配列に変換します。
 * @param ip - IPv4アドレス文字列 (例: "192.168.1.1")。
 * @returns IPアドレスを表すUint8Array。
 */
function ipAddrToBytes(ip: string): Uint8Array {
  return new Uint8Array(ip.split('.').map(Number));
}

/**
 * 指定されたホスト文字列がIPv4アドレス形式であるかどうかを検証します。
 * @param host - 検証するホスト文字列。
 * @returns ホストがIPv4アドレスの場合はtrue、そうでない場合はfalse。
 */
function isIPv4(host: string): boolean {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(host);
}

/**
 * 指定されたプロトコル、ターゲット、および認証情報に基づいてプロキシ接続要求パケットを生成します。
 * @param protocol - プロキシプロトコル ("socks5", "socks4", "http")。
 * @param target - ターゲットのホストとポートのタプル (例: ["example.com", 80])。
 * @param auth - オプションの認証情報オブジェクト。
 * @param auth.username - ユーザー名。
 * @param auth.password - パスワード。
 * @returns 生成されたパケットを表すUint8Array。
 * @throws サポートされていないプロトコルが指定された場合、またはSOCKS5でドメイン名が長すぎる場合。
 */
function generatePacket(
  protocol: string,
  target: [string, number],
  auth?: { username?: string | null; password?: string | null },
): Uint8Array {
  const encoder = new TextEncoder();

  switch (protocol) {
    case "socks5": { // SOCKS5接続要求パケットは認証情報を含まない
      const portBytes = new Uint8Array([(target[1] >> 8) & 0xff, target[1] & 0xff]);
      let atypFieldAndAddr: Uint8Array;

      if (isIPv4(target[0])) {
        atypFieldAndAddr = new Uint8Array([
          0x01, // ATYP: IPv4
          ...ipAddrToBytes(target[0]), // DST.ADDR (4 bytes)
        ]);
      } else {
        // ドメイン名でない場合はドメイン名と仮定します。必要に応じてATYP 0x04のIPv6チェックを追加します。
        const domainBytes = encoder.encode(target[0]);
        if (domainBytes.length > 255) {
          throw new Error("SOCKS5: ドメイン名が長すぎます。");
        }
        atypFieldAndAddr = new Uint8Array([
          0x03, // ATYP: ドメイン名
          domainBytes.length, // ドメイン名の長さ
          ...domainBytes, // DST.ADDR (可変長)
        ]);
      }

      return new Uint8Array([
        0x05, // VER
        0x01, // CMD (CONNECT)
        0x00, // RSV
        ...atypFieldAndAddr,
        ...portBytes, // DST.PORT
      ]);
    }
    case "socks4":
      const userIdBytes = auth && auth.username ? encoder.encode(auth.username) : new Uint8Array();
      return new Uint8Array([
        0x04, // VER
        0x01, // CMD (CONNECT)
        (target[1] >> 8) & 0xff, // DSTPORT
        target[1] & 0xff,
        ...ipAddrToBytes(target[0]), // DSTIP
        ...userIdBytes,
        0x00, // Null terminator for USERID
      ]);
    case "http":
      let request = `CONNECT ${target[0]}:${target[1]} HTTP/1.1\r\n`;
      request += `Host: ${target[0]}:${target[1]}\r\n`;
      if (auth && auth.username) {
        // btoa is available in Deno's global scope
        const credentials = `${auth.username}:${auth.password || ""}`;
        const encodedCredentials = globalThis.btoa(credentials);
        request += `Proxy-Authorization: Basic ${encodedCredentials}\r\n`;
      }
      request += `Proxy-Connection: keep-alive\r\n`;
      request += `Connection: keep-alive\r\n\r\n`;
      return encoder.encode(request);
    default:
      throw new Error(`Unsupported protocol for generating packet: ${protocol}`);
  }
}

/**
 * プロキシサーバーからの応答が成功を示しているかどうかを確認します。
 * @param protocol - 使用されたプロキシプロトコル ("socks5", "socks4", "http")。
 * @param data - プロキシサーバーからの応答データを含むUint8Array。
 * @returns 応答が成功を示している場合はtrue、そうでない場合はfalse。
 */
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

/**
 * プロキシ文字列を解析し、プロトコル、ホスト、ポート、および認証情報を抽出します。
 * @param proxy - プロキシ文字列 (例: "socks5://user:pass@host:port" または "http://host:port")。
 * @returns プロトコル、ホスト、ポート番号、ユーザー名 (存在する場合)、パスワード (存在する場合) を含むタプル。
 *          ポートが指定されていない場合のデフォルトポートは1080です。
 */
function parseProxy(proxy: string): [string, string, number, string | null, string | null] {
  const [protocol, origin] = proxy.split("://");
  const [auth, address] = origin.includes("@") ? origin.split("@") : ["", origin];
  const [rawUsername, rawPassword] = auth.includes(":") ? auth.split(":") : [auth, ""];
  const [host, port] = address.split(":");
  const portNum = port ? parseInt(port) : 1080;

  const username: string | null = rawUsername !== "" ? rawUsername : null;
  const password: string | null = rawPassword !== "" ? rawPassword : null;

  return [protocol, host, portNum, username, password];
}

/**
 * 1つ以上のプロキシサーバーを経由してターゲットへの接続を確立します。
 * 最初のプロキシのみが認証をサポートします。チェーン内の後続のプロキシは認証なしとみなされます。
 * @param proxies - プロキシサーバーの文字列の配列。最初のプロキシから順に接続されます。
 *                  各文字列の形式は "protocol://[username:password@]host:port" です。
 * @param target - 最終的な接続先のホストとポートのタプル (例: ["example.com", 80])。
 * @param timeout - 各ネットワーク操作のタイムアウト時間 (ミリ秒単位)。デフォルトは10000ms。
 * @returns ターゲットへのプロキシ接続を表す Deno.Conn オブジェクト。
 * @throws プロキシリストが空の場合、SOCKS5認証に失敗した場合、
 *         接続が途中で閉じられた場合、またはハンドシェイクに失敗した場合。
 */
async function proxySocket(proxies: string[], target: [string, number], timeout = 10000): Promise<Deno.Conn> {
  if (proxies.length === 0) {
    throw new Error("Proxy list cannot be empty.");
  }

  let conn: Deno.Conn | null = null;
  const firstProxyInfo = parseProxy(proxies[0]);
  const [
    firstProxyProtocol,
    firstProxyHost,
    firstProxyPort,
    firstProxyUsername,
    firstProxyPassword,
  ] = firstProxyInfo;
  let currentProtocolForHandshake = firstProxyProtocol;
  const encoder = new TextEncoder();

  try {
    conn = await deadline(Deno.connect({ hostname: firstProxyHost, port: firstProxyPort }), timeout);

    // Authentication for the first proxy
    if (firstProxyProtocol === "socks5") {
      // 1. Send supported authentication methods
      // We offer: No Authentication (0x00) and Username/Password (0x02) if username is present.
      const authMethods = [0x00]; // METHOD_NO_AUTH
      if (firstProxyUsername) { // Password can be null/empty, but username must exist for USER/PASS
        authMethods.push(0x02); // METHOD_USER_PASS
      }
      const authMethodsPacket = new Uint8Array([0x05, authMethods.length, ...authMethods]);
      await deadline(conn.write(authMethodsPacket), timeout);

      // 2. Receive chosen authentication method
      const authMethodResponse = new Uint8Array(2); // VER, METHOD
      const authMethodBytesRead = await deadline(conn.read(authMethodResponse), timeout);

      if (authMethodBytesRead === null || authMethodBytesRead < 2) {
        throw new Error("SOCKS5 auth method negotiation failed: connection closed or insufficient data.");
      }
      if (authMethodResponse[0] !== 0x05) { // VER
        throw new Error("SOCKS5 auth method negotiation failed: invalid version.");
      }

      const selectedMethod = authMethodResponse[1]; // METHOD

      if (selectedMethod === 0x02) { // Username/Password authentication
        if (!firstProxyUsername) {
          throw new Error("SOCKS5 selected Username/Password auth, but no username provided.");
        }
        const userBytes = encoder.encode(firstProxyUsername);
        const passBytes = encoder.encode(firstProxyPassword || ""); // Password can be empty

        const userPassAuthPacket = new Uint8Array([
          0x01, // Auth version for username/password sub-negotiation
          userBytes.length,
          ...userBytes,
          passBytes.length,
          ...passBytes,
        ]);
        await deadline(conn.write(userPassAuthPacket), timeout);

        const authResultResponse = new Uint8Array(2); // VER, STATUS
        const authResultBytesRead = await deadline(conn.read(authResultResponse), timeout);
        if (authResultBytesRead === null || authResultBytesRead < 2) {
          throw new Error("SOCKS5 username/password auth failed: connection closed or insufficient data.");
        }
        // VER should be 0x01 for username/password sub-negotiation response
        if (authResultResponse[0] !== 0x01 || authResultResponse[1] !== 0x00) { // STATUS 0x00 = success
          throw new Error(`SOCKS5 username/password authentication failed. Status: ${authResultResponse[1]}`);
        }
      } else if (selectedMethod === 0x00) {
        // No authentication required, proceed
      } else if (selectedMethod === 0xff) { // 0xFF indicates no acceptable methods found by proxy
        throw new Error("SOCKS5 authentication failed: no acceptable methods offered were accepted by the proxy.");
      } else {
        throw new Error(`SOCKS5 authentication failed: unsupported method selected by proxy: ${selectedMethod}`);
      }
    }
    // For HTTP and SOCKS4, authentication is part of the connect request generated by generatePacket

    const hops: Array<[string, number, string?]> = [];
    for (let i = 1; i < proxies.length; i++) {
      const nextProxyInfo = parseProxy(proxies[i]);
      hops.push([nextProxyInfo[1], nextProxyInfo[2], nextProxyInfo[0]]);
    }
    hops.push([target[0], target[1], undefined]);

    const firstProxyAuthCredentials = { username: firstProxyUsername, password: firstProxyPassword };

    for (const hop of hops) {
      const [hostForNextHop, portForNextHop, protocolOfNextProxy] = hop;

      const packet = generatePacket(
        currentProtocolForHandshake,
        [hostForNextHop, portForNextHop],
        // Pass auth credentials only if the current handshake protocol is HTTP or SOCKS4
        // SOCKS5 authentication is handled separately before this stage.
        (currentProtocolForHandshake === "http" || currentProtocolForHandshake === "socks4")
          ? firstProxyAuthCredentials
          : undefined,
      );
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
        // Note: This simplified model assumes that if chaining proxies, 
        // subsequent proxies either don't require auth or the context/protocol handles it.
        // Auth for subsequent proxies in a chain (proxies[1], proxies[2]...) is not explicitly
        // handled with their own credentials here.
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
        // console.error("Error closing connection:", closeError);
      }
    }
    const errorMessage = e instanceof Error ? e.message : String(e);
    throw new Error(`Proxy socket setup failed: ${errorMessage}`);
  }
}

export { proxySocket };
