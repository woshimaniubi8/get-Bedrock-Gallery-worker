// Endpoints used for Microsoft & Xbox Live Authentication
const Endpoints = {
	LiveDeviceCodeRequest: 'https://login.live.com/oauth20_connect.srf',
	LiveTokenRequest: 'https://login.live.com/oauth20_token.srf',
	XboxUserAuth: 'https://user.auth.xboxlive.com/user/authenticate',
	XboxXSTSAuth: 'https://xsts.auth.xboxlive.com/xsts/authorize',
};
let MCtokenexpiryTime;
let XboxexpiryTime;
let Xbox1expiryTime;
export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const path = url.pathname;

		// Route requests based on the URL path
		if (path === '/login') {
			// This is the interactive endpoint YOU will visit to authorize the application.
			return this.handleLogin(request, env, ctx);
		} else if (path.startsWith('/getGallery')) {
			// This is the public endpoint for fetching images.
			return this.handleGetGallery(request, env, ctx);
		} else {
			return new Response(
				'<h3>先用 <a href="/login">/login</a> 初始化token(初次部署时)<br>然后用 <a href="/getGallery?xuid=">/getGallery?xuid=</a> 或者 <a href="/getGallery?gt=">/getGallery?gt=</a> 获取背景图</h3><p>worker - 1.0</p>',
				{
					status: 200,
					headers: { 'Content-Type': 'text/html;charset=utf-8' },
				}
			);
		}
	},

	/**
	 * Handles the /getGallery?xuid=... request.
	 * This is non-interactive and relies on a token being present in the KV store.
	 */
	async handleGetGallery(request, env, ctx) {
		const url = new URL(request.url);
		const gt = url.searchParams.get('gt');
		let xuid = url.searchParams.get('xuid');

		if (!xuid && !gt) {
			return new Response(JSON.stringify({ error: 'Missing xuid parameter' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}
		if (!xuid) {
			xuid = await this.handleGetXuid(gt, env, null);
			//console.log(xuid);
		}
		try {
			if (Math.floor((MCtokenexpiryTime - Date.now()) / 1000) - 300 < 0) {
				const st = await env.TOKEN_KV.get(`sessionTicket`);
				await this.getAndCacheMCToken(st, env);
				console.log('MC Token失效，正在尝试获取新Token');
			}
			// 1. Try to get the MC Token from the cache.
			let mcToken = await env.TOKEN_KV.get('mcToken');
			if (!mcToken) {
				mcToken = await this.getAndCacheMCToken(st, env);
			}

			// 2. Use the token to fetch the background image.
			const galleryResponse = await fetch(
				`https://persona-secondary.franchise.minecraft-services.net/api/v1.0/gallery/featured/xuid/${xuid}`,
				{
					headers: {
						authorization: mcToken,
						accept: '*/*',
						'user-agent': 'libhttpclient/1.0.0.0',
					},
				}
			);

			if (!galleryResponse.ok) {
				return new Response(JSON.stringify({ error: 'Failed to fetch background image', status: galleryResponse.status }), {
					status: galleryResponse.status,
				});
			}

			// 3. Return the image directly.
			return new Response(galleryResponse.body, {
				status: galleryResponse.status,
				headers: galleryResponse.headers,
			});
		} catch (error) {
			console.error('Error in /getGallery:', error.message);
			return new Response(JSON.stringify({ error: error.message }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	},

	/**
	 * Handles the /login request.
	 * This starts the Device Code flow and must be triggered manually by an administrator.
	 */
	async handleLogin(request, env, ctx) {
		try {
			// 1. Request a device code from Microsoft.
			const deviceCodeResponse = await fetch(Endpoints.LiveDeviceCodeRequest, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					client_id: env.CLIENT_ID,
					scope: 'XboxLive.signin offline_access',
					response_type: 'device_code',
				}).toString(),
			}).then((res) => res.json());

			if (deviceCodeResponse.error) {
				throw new Error(`Failed to get device code: ${deviceCodeResponse.error_description}`);
			}

			const { user_code, verification_uri, device_code, expires_in, interval } = deviceCodeResponse;

			// 2. IMPORTANT: Start polling for the token in the background.
			// ctx.waitUntil() allows the worker to continue processing after the response has been sent.
			// This is how we handle the long-running polling process without timing out the initial request.
			ctx.waitUntil(this.pollForTokenAndStore(device_code, interval, expires_in, env));

			// 3. Immediately return the instructions to the user.
			//	const message = `Please authorize this application by visiting: ${verification_uri} and entering the code: ${user_code} or open \n ${verification_uri}?otc=${user_code}`;
			const message = `<body><h2>Please authorize this application by visiting: ${verification_uri} and entering the code: ${user_code} or open \n ${verification_uri}?otc=${user_code}</h2><script>document.location = '${verification_uri}?otc=${user_code}'</script></body>`;
			return new Response(message, {
				headers: { 'Content-Type': 'text/html' },
			});
		} catch (error) {
			console.error('Error in /login:', error.stack);
			return new Response(JSON.stringify({ error: error.message }), { status: 500 });
		}
	},
	async refreshAccessToken(env) {
		console.log('正在尝试刷新访问令牌');
		const refreshToken = await env.TOKEN_KV.get('refreshToken');
		if (!refreshToken) {
			throw new Error('No refresh token found. Please login again.');
		}

		const response = await fetch(Endpoints.LiveTokenRequest, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				client_id: env.CLIENT_ID,
				grant_type: 'refresh_token',
				refresh_token: refreshToken,
				scope: 'XboxLive.signin offline_access',
			}),
		});

		const tokenData = await response.json();

		if (!response.ok) {
			console.error('刷新AccessToken失败:', tokenData.error_description);
			// If the refresh token is invalid, you might need to prompt for re-login.
			// For simplicity here, we'll just throw an error.
			throw new Error('Could not refresh the access token. Please log in again.');
		}

		// Store the new tokens
		await env.TOKEN_KV.put('accessToken', tokenData.access_token, { expirationTtl: 3600 - 100 });
		await env.TOKEN_KV.put('accessTokenTime', Date.now());
		await env.TOKEN_KV.put('refreshToken', tokenData.refresh_token);

		console.log('成功刷新AccessToken.');
		return tokenData.access_token;
	},
	/**
	 * Polls Microsoft's servers to see if the user has approved the login request.
	 * Once approved, it runs the full token chain and stores the final MC Token in KV.
	 * This function is designed to be run in the background via ctx.waitUntil().
	 */
	async pollForTokenAndStore(device_code, interval, expires_in, env) {
		const expiryTime = Date.now() + expires_in * 1000 - 10000; // 10-second buffer
		let polling = true;

		while (polling && Date.now() < expiryTime) {
			await new Promise((resolve) => setTimeout(resolve, interval * 1000));

			try {
				const tokenResponse = await fetch(Endpoints.LiveTokenRequest, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({
						client_id: env.CLIENT_ID,
						device_code: device_code,
						grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					}).toString(),
				}).then((res) => res.json());

				if (tokenResponse.error) {
					if (tokenResponse.error === 'authorization_pending') {
						console.log('等待网页登录...');
						continue;
					} else {
						throw new Error(`Error polling for token: ${tokenResponse.error_description}`);
					}
				}

				polling = false;
				console.log('成功获取AccreeToken');

				const { access_token, refresh_token } = tokenResponse;

				// Store both the access and refresh tokens
				await env.TOKEN_KV.put('accessToken', access_token, { expirationTtl: 3600 - 100 });
				await env.TOKEN_KV.put('accessTokenTime', Date.now());
				await env.TOKEN_KV.put('refreshToken', refresh_token);

				const xboxToken = await this.getXboxToken(access_token, 0, env);
				const GametagxboxToken = await this.getXboxToken(access_token, 1, env);
				const sessionTicket = await this.getSessionTicket(xboxToken, env);
				await env.TOKEN_KV.put(`sessionTicket`, sessionTicket);
				await this.getAndCacheMCToken(sessionTicket, env);

				console.log('Successfully acquired and cached all tokens.');
			} catch (e) {
				console.error('Error during token polling:', e.message);
				polling = false;
			}
		}

		if (polling) {
			console.error('Login process timed out. The user did not approve in time.');
		}
	},

	// The following helper functions are mostly the same as before, but adapted
	// to use the access token from the device flow instead of a password.

	async handleGetXuid(request, env, ctx) {
		const gamertag = request;
		if (!gamertag) {
			return new Response(JSON.stringify({ error: 'Missing gamertag parameter' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		//	try {
		// 1. Get a general-purpose Xbox Live API token. This is different from the Minecraft token.
		const act = await env.TOKEN_KV.get('accessToken');
		//	console.log(act);
		const xboxApiToken = await this.getXboxToken(act, 1, env);
		//console.log(1222);
		// 2. Call the Xbox Live API to get the profile settings for the given Gamertag.
		//console.log(xboxApiToken);
		const encodedGamertag = encodeURIComponent(gamertag);
		const res = await fetch(
			`https://profile.xboxlive.com/users/gt(${encodedGamertag})/profile/settings?settings=GameDisplayName,Gamertag,GameDisplayPicRaw,Gamerscore,TenureLevel`,
			{
				method: 'GET',
				headers: {
					Connection: 'keep-alive',
					Accept: '*/*',
					'Accept-Encoding': 'gzip, deflate, br',
					'Content-Type': 'application/json',
					Authorization: xboxApiToken,
					'x-xbl-contract-version': '2',
				},
			}
		);

		if (!res.ok) {
			throw new Error(`Failed to get XUID from Xbox API. Status: ${res.status} ${res.statusText}`);
		}
		//	console.log(1222);
		const data = await res.json();
		const player = data.profileUsers;

		if (!player || player.length === 0 || !player[0].id) {
			throw new Error('Gamertag not found or API returned no data.');
		}

		const xuid = player[0].id;
		return xuid;
		//	} catch (error) {
		console.error('Error in /getXuid:', error.message);
		return new Response(JSON.stringify({ error: error.message }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
		//		}
	},

	async getXboxToken(sAccessToken, type, env) {
		let msAccessToken = sAccessToken;
		if (Math.floor(((type ? Xbox1expiryTime : XboxexpiryTime) - Date.now()) / 1000) - 300 > 0) {
			const tk = await env.TOKEN_KV.get(`XboxToken_${type}`);
			if (tk) {
				console.log('Xbox Token 有效');
				return tk;
			}
		}
		const agt = await env.TOKEN_KV.get('accessTokenTime');
		if (Math.floor((agt - Date.now()) / 1000) - 100 < 0) {
			console.log('AccessToken 失效，尝试获取新Token');
			msAccessToken = await this.refreshAccessToken(env);
		}

		// A simple way to check if the access token needs refreshing is to try the request and refresh if it fails with an auth error.
		// However, a more proactive approach is to assume it might be expired and refresh. For simplicity in this example,
		// we will refresh the access token each time we need a new Xbox token. A more advanced implementation
		// could store the access token's expiry time and only refresh when needed.

		try {
			return await this.fetchXboxToken(msAccessToken, type, env);
		} catch (error) {
			if (error.message.includes('XBL Auth Error')) {
				// A more specific error check might be needed
				console.log('Xbox Token获取失败，正在尝试刷新访问令牌。');
				const newAccessToken = await this.refreshAccessToken(env);
				return await this.fetchXboxToken(newAccessToken, type, env);
			} else {
				throw error;
			}
		}
	},

	async fetchXboxToken(msAccessToken, type, env) {
		console.log('Xbox Token 失效，尝试获取新Token');
		try {
			const xblResponse = await fetch(Endpoints.XboxUserAuth, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'x-xbl-contract-version': '1' },
				body: JSON.stringify({
					RelyingParty: 'http://auth.xboxlive.com',
					TokenType: 'JWT',
					Properties: { AuthMethod: 'RPS', SiteName: 'user.auth.xboxlive.com', RpsTicket: `d=${msAccessToken}` },
				}),
			});

			const xblData = await xblResponse.json();
			if (xblData.error) throw new Error(`XBL Auth Error: ${xblData.message}`);

			const relayingparty = type ? 'http://xboxlive.com' : 'https://b980a380.minecraft.playfabapi.com/';
			const xstsResponse = await fetch(Endpoints.XboxXSTSAuth, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'x-xbl-contract-version': '1' },
				body: JSON.stringify({
					RelyingParty: relayingparty,
					TokenType: 'JWT',
					Properties: { SandboxId: 'RETAIL', UserTokens: [xblData.Token] },
				}),
			});

			const xstsData = await xstsResponse.json();
			if (xstsData.XErr) throw new Error(`XSTS Auth Error (${xstsData.XErr}): ${xstsData.Message}`);

			const userHash = xstsData.DisplayClaims.xui[0].uhs;
			const xstsToken = xstsData.Token;
			const expiryTime = new Date(xstsData.NotAfter).getTime();
			if (type) {
				Xbox1expiryTime = expiryTime;
			} else {
				XboxexpiryTime = expiryTime;
			}

			const now = Date.now();
			const ttlInSeconds = Math.max(60, Math.floor((expiryTime - now) / 1000) - 300);

			const token = `XBL3.0 x=${userHash};${xstsToken}`;
			await env.TOKEN_KV.put(`XboxToken_${type}`, token, { expirationTtl: ttlInSeconds });
			console.log('Xbox Token TTL:', ttlInSeconds);
			return token;
		} catch (e) {
			console.error('FetchXboxToken() => ', e);
		}
	},

	async getSessionTicket(xboxToken, env) {
		const response = await fetch(`https://${env.PLAYFAB_TITLE_ID}.playfabapi.com/Client/LoginWithXbox`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				CreateAccount: true,
				InfoRequestParameters: { GetPlayerProfile: true },
				TitleId: env.PLAYFAB_TITLE_ID,
				XboxToken: xboxToken,
			}),
		});
		const data = await response.json();
		if (data.code !== 200 || !data.data?.SessionTicket) throw new Error('Failed to get Session Ticket: ' + data.errorMessage);
		return data.data.SessionTicket;
	},

	async getAndCacheMCToken(sessionTicket, env) {
		const response = await fetch('https://authorization.franchise.minecraft-services.net/api/v1.0/session/start', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				device: {
					applicationType: 'MinecraftPE',
					gameVersion: '1.21.100',
					id: crypto.randomUUID(),
					memory: '34188656640',
					platform: 'Windows10',
					playFabTitleId: env.PLAYFAB_TITLE_ID,
					storePlatform: 'uwp.store',
					type: 'Windows10',
				},
				user: { language: 'zh-CN', token: sessionTicket, tokenType: 'PlayFab' },
			}),
		});
		const data = await response.json();
		if (!data.result?.authorizationHeader) throw new Error('Failed to get MC Token: ' + JSON.stringify(data));

		const mcToken = data.result.authorizationHeader;
		const validUntil = data.result.validUntil;
		MCtokenexpiryTime = new Date(validUntil).getTime();
		const now = Date.now();
		const ttlInSeconds = Math.max(60, Math.floor((MCtokenexpiryTime - now) / 1000) - 300); // 5 min buffer

		await env.TOKEN_KV.put('mcToken', mcToken, { expirationTtl: ttlInSeconds });
		console.log(`成功缓存MC Token TTL: ${ttlInSeconds}s`);
		return { mcToken, validUntil };
	},
};
