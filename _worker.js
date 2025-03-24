// Please comply with local laws when using.
// Path /sub View subscription information.

import { connect } from 'cloudflare:sockets';

// 缓存 KV 数据
let cachedUserID = null;
let cachedProxyIP = null;
let lastFetchTime = 0;
const CACHE_TTL = 86400000; // 24小时缓存，因为配置不常改变

// 从KV获取并直接替换默认值
async function initConfig(env) {
	const now = Date.now();
	
	// 使用缓存数据如果未过期
	if (cachedUserID && cachedProxyIP && (now - lastFetchTime) < CACHE_TTL) {
		return;
	}

	try {
		// 直接使用 UUID 和 PROXYIP 作为 key
		const uuid = await env.yumi.get('UUID');
		const proxyip = await env.yumi.get('PROXYIP');
		
		console.log('KV values:', { uuid, proxyip }); // 添加日志
		
		if (uuid) cachedUserID = uuid;
		if (proxyip) cachedProxyIP = proxyip;
		lastFetchTime = now;
		
		console.log('Cached values:', { cachedUserID, cachedProxyIP }); // 添加日志
	} catch (err) {
		console.error('Failed to fetch KV:', err);
	}
}

// 获取当前配置
function getCurrentConfig() {
	const userID = cachedUserID || 'cd0b5f83-3729-4962-92fb-90045fb2533f';
	const bestIP = "bestcf.030101.xyz"; // 空字符串表示未设置
	const proxyIP = cachedProxyIP || "bpb.yousef.isegaro.com";

	console.log('Current config:', { userID, bestIP, proxyIP }); // 添加日志

	if (!isValidUUID(userID)) {
		throw new Error('The uuid is not set');
	}

	const config = {
		userID,
		bestIP,
		proxyIP,
		main: bestIP || proxyIP
	};
	
	console.log('Final config:', config); // 添加日志
	
	return config;
}

export default {
	async fetch(request, env, ctx) {
		try {
			// 初始化配置
			await initConfig(env);
			
			// 获取当前配置
			const config = getCurrentConfig();
			
			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);

			if (url.pathname === '/sub') {
				const allLinks = generateAllLinks(url.host, config);
				const base64Links = btoa(allLinks.join('\n'));
				return new Response(base64Links, {
					status: 200,
					headers: {
						"Content-Type": "text/plain;charset=utf-8"
					}
				});
			}

			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				switch (url.pathname) {
					case '/':
						const responseText = generateResponseText(request.cf, url.host, config);
						return new Response(responseText, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8"
							}
						});
					default:
						return new Response('Not found', {
							status: 404
						});
				}
			} else {
				return await ymyuuuOverWSHandler(request, config);
			}
		} catch (err) {
			console.error(`Error handling request: ${err.stack || err}`);
			return new Response(`Internal Server Error: ${err.message}`, {
				status: 500,
				headers: {
					'Content-Type': 'text/plain;charset=utf-8'
				}
			});
		}
	},
};

function generateResponseText(cf, host, config) {
	const { userID, bestIP, proxyIP } = config;
	// 获取请求中的 Cloudflare 特定数据
	const cloudflareData = JSON.stringify(cf, null, 2);
	const additionalData = `GitHub: https://github.com/ymyuuu\nTelegram: https://t.me/HeroCore\n\nHost: ${host}${bestIP ? '\nBestIP: ' + bestIP : ''}\nProxyIP: ${proxyIP}\nUUID: ${userID}`;
	let responseText = `${cloudflareData}\n\n${additionalData}`;

	const isWorkersDev = host.endsWith('workers.dev');
	if (isWorkersDev) {
		const httpLinks = generateLinks(host, [80, 8080, 8880, 2052, 2086, 2095], 'none', 'none', false, config);
		responseText += `\n\nHTTP Port: 80, 8080, 8880, 2052, 2086, 2095\n${httpLinks.join('\n')}`;
	} else {
		const httpsLinks = generateLinks(host, [443, 8443, 2053, 2096, 2087, 2083], 'none', 'tls', true, config);
		responseText += `\n\nHTTPS Port: 443, 8443, 2053, 2096, 2087, 2083\n${httpsLinks.join('\n')}`;
	}

	return responseText;
}

function generateLinks(host, ports, encryption, security, isHTTPS = false, config) {
	const { userID, main } = config;
	const protocol = "dmxlc3M="; // Base64 编码后的 "vless"
	const baseConfig = `${atob(protocol)}://${userID}@${main}`;
	return ports.map(port => 
		`${baseConfig}:${port}?encryption=${encryption}&security=${security}${isHTTPS ? `&sni=${host}` : ''}&fp=random&type=ws&host=${host}&path=%2F%3D2048#CFW_${port}`
	);
}

function generateAllLinks(host, config) {
	const isWorkersDev = host.endsWith('workers.dev');
	if (isWorkersDev) {
		return generateLinks(host, [80, 8080, 8880, 2052, 2086, 2095], 'none', 'none', false, config);
	} else {
		return generateLinks(host, [443, 8443, 2053, 2096, 2087, 2083], 'none', 'tls', true, config);
	}
}

async function ymyuuuOverWSHandler(request, config) {
	const { userID, bestIP, proxyIP, main } = config;

	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = ( /** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				ymyuuuVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processymyuuuHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '
				} `;
			if (hasError) {
				throw new Error(message);
				return;
			}
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error(
						'UDP proxy only enable for DNS which is port 53'
					);
					return;
				}
			}
			const ymyuuuResponseHeader = new Uint8Array([ymyuuuVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				const {
					write
				} = await handleUDPOutBound(webSocket, ymyuuuResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData,
				webSocket, ymyuuuResponseHeader, log, config);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}


async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, ymyuuuResponseHeader,
	log, config) {

	async function connectAndWrite(address, port) {
		try {
			const tcpSocket = connect({
				hostname: address,
				port: port,
				timeout: 10000,  // 增加超时时间
				allowHalfOpen: false,  // 关闭半开连接，减少资源占用
				keepAlive: false,  // 关闭 keepAlive，让 CF 自己管理连接
			});
			remoteSocket.value = tcpSocket;
			log(`connected to ${address}:${port}`);
			const writer = tcpSocket.writable.getWriter();
			await writer.write(rawClientData);
			writer.releaseLock();
			return tcpSocket;
		} catch (error) {
			log(`Failed to connect to ${address}:${port}: ${error}`);
			throw error;
		}
	}

	async function retry() {
		const maxRetries = 3;
		let retryCount = 0;
		
		while (retryCount < maxRetries) {
			try {
				const tcpSocket = await connectAndWrite(config.proxyIP, portRemote);
				tcpSocket.closed.catch((error) => {
					console.log('retry tcpSocket closed error', error);
				}).finally(() => {
					safeCloseWebSocket(webSocket);
				})
				remoteSocketToWS(tcpSocket, webSocket, ymyuuuResponseHeader, null, log);
				return;
			} catch (error) {
				retryCount++;
				if (retryCount === maxRetries) {
					// 所有重试失败，使用直连
					const tcpSocket = await connectAndWrite(addressRemote, portRemote);
					remoteSocketToWS(tcpSocket, webSocket, ymyuuuResponseHeader, null, log);
				}
				// 短暂延迟后重试
				await new Promise(resolve => setTimeout(resolve, 1000));
			}
		}
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	remoteSocketToWS(tcpSocket, webSocket, ymyuuuResponseHeader, retry, log);
}


function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', ( /** @type {{ data: any; }} */ event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});


			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});
			webSocketServer.addEventListener('error', ( /** @type {any} */ err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			// for ws 0rtt
			const {
				earlyData,
				error
			} = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;

}

function processymyuuuHeader(
	ymyuuuBuffer,
	userID
) {
	if (ymyuuuBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(ymyuuuBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	if (stringify(new Uint8Array(ymyuuuBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(ymyuuuBuffer.slice(17, 18))[0];

	const command = new Uint8Array(
		ymyuuuBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	if (command === 1) {} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = ymyuuuBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		ymyuuuBuffer.slice(addressIndex, addressIndex + 1)
	);

	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				ymyuuuBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				ymyuuuBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				ymyuuuBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				ymyuuuBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return {
				hasError: true,
					message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		ymyuuuVersion: version,
		isUDP,
	};
}

async function remoteSocketToWS(remoteSocket, webSocket, ymyuuuResponseHeader, retry, log) {
	let remoteChunkCount = 0;
	let chunks = [];
	let ymyuuuHeader = ymyuuuResponseHeader;
	let hasIncomingData = false;
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {},
				async write(chunk, controller) {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (ymyuuuHeader) {
						webSocket.send(await new Blob([ymyuuuHeader, chunk]).arrayBuffer());
						ymyuuuHeader = null;
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch(( /** @type {{ stack: any; }} */ error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return {
			error: null
		};
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return {
			earlyData: arryBuffer.buffer,
			error: null
		};
	} catch (error) {
		return {
			error
		};
	}
}

function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[
			offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[
			offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset +
			9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
		byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

async function handleUDPOutBound(webSocket, ymyuuuResponseHeader, log) {

	let isymyuuuHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {}
	});

	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch('https://1.1.1.1/dns-query', {
				method: 'POST',
				headers: {
					'content-type': 'application/dns-message',
				},
				body: chunk,
			})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isymyuuuHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([ymyuuuResponseHeader, udpSizeBuffer,
						dnsQueryResult
					]).arrayBuffer());
					isymyuuuHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error)
	});
	const writer = transformStream.writable.getWriter();

	return {
		write(chunk) {
			writer.write(chunk);
		}
	};
}
