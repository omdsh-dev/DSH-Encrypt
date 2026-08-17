window.__ModuleLoader__.load({
	id: "dsh-encrypt",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		const React = require("react");
		//#region lib/client.js
		/**
		 * Settings → 加密安全: the browser surface for dsh-encrypt's password
		 * lifecycle. Talks to the host over the exact routes the `dsh-encrypt/web`
		 * row registers. The raw password never crosses the wire: this bundle
		 * derives its SHA3-256 digest (pure JS, Keccak-f[1600]) and POSTs only
		 * `{ digest }`.
		 *
		 * Remembered logins: a slider sets how long a localhost unlock stays
		 * valid without the password — 0 = every time, 1..30 days, forever.
		 * The server issues an HttpOnly ticket cookie; the panel then
		 * auto-unlocks on page load for the configured window. Non-localhost
		 * visits always require the password and cannot modify it.
		 *
		 * States:
		 *   plain              — no password set; credentials sit as plaintext
		 *                        YAML. Form: set the first password (typed twice).
		 *   encrypted+locked   — a password protects the file but this dsh
		 *                        process has not unlocked it (restart). Form:
		 *                        enter the password to unlock.
		 *   encrypted+unlocked — the store is unlocked. Forms: change the
		 *                        password, or remove it (back to plaintext).
		 * @module dsh-encrypt/client
		 */
		// ── SHA3-256 (Keccak-f[1600], pure JS) ──────────────────────────────
		// WebCrypto has no SHA3, so the digest is computed here; only the
		// lowercase hex digest ever leaves the browser.
		const KECCAK_RC = [0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an, 0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n];
		const KECCAK_RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
		const KECCAK_PI = [0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4];
		const MASK64 = (1n << 64n) - 1n;
		function rotl(x, n) {
			return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
		}
		function keccakF(lanes) {
			for (let round = 0; round < 24; round++) {
				const c = [];
				for (let x = 0; x < 5; x++) c[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
				const d = [];
				for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
				for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) lanes[x + 5 * y] ^= d[x];
				const b = new Array(25).fill(0n);
				for (let i = 0; i < 25; i++) b[KECCAK_PI[i]] = rotl(lanes[i], KECCAK_RHO[i]);
				for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) lanes[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
				lanes[0] ^= KECCAK_RC[round];
			}
			return lanes;
		}
		/** Lowercase hex SHA3-256 of a text. */
		function sha3_256Hex(text) {
			const bytes = new TextEncoder().encode(String(text));
			const rate = 136;
			const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
			padded.set(bytes);
			padded[bytes.length] = 0x06;
			padded[padded.length - 1] |= 0x80;
			let state = new Array(25).fill(0n);
			for (let off = 0; off < padded.length; off += rate) {
				for (let i = 0; i < rate; i += 8) {
					let word = 0n;
					for (let b = 0; b < 8; b++) word |= BigInt(padded[off + i + b]) << BigInt(8 * b);
					state[i / 8] ^= word;
				}
				state = keccakF(state);
			}
			const out = new Uint8Array(32);
			for (let i = 0; i < 4; i++) {
				let word = state[i];
				for (let b = 0; b < 8; b++) {
					out[i * 8 + b] = Number(word & 0xffn);
					word >>= 8n;
				}
			}
			let hex = "";
			for (let i = 0; i < out.length; i++) hex += out[i].toString(16).padStart(2, "0");
			return hex;
		}
		const LABEL = { color: "var(--dsw-alias-label-primary)", fontSize: 14, lineHeight: "22px", margin: 0 };
		const HINT = { color: "var(--dsw-alias-label-tertiary)", fontSize: 12, lineHeight: "18px", margin: "8px 0 0" };
		const WARN = { color: "var(--dsw-alias-state-warn-label)", fontSize: 12, lineHeight: "18px", margin: "8px 0 0" };
		const OK = { color: "var(--dsw-alias-state-success-primary)", fontSize: 12, lineHeight: "18px", margin: "8px 0 0" };
		const FIELD = {
			boxSizing: "border-box", width: "100%", height: 36, margin: "4px 0 0",
			padding: "0 12px", border: "1px solid var(--dsw-alias-border-l2)", borderRadius: 18,
			background: "var(--dsw-alias-fill-primary)", color: "var(--dsw-alias-label-primary)",
			font: "inherit", fontSize: 14, outline: "none"
		};
		const BUTTON = {
			boxSizing: "border-box", height: 36, padding: "0 14px", margin: "12px 0 0",
			border: "none", borderRadius: 18, cursor: "pointer", font: "inherit", fontSize: 14,
			background: "var(--dsw-alias-button-primary-fill)", color: "var(--dsw-alias-label-primary-foreground)"
		};
		const CARD = {
			border: "1px solid var(--dsw-alias-border-l2)", borderRadius: 12,
			padding: "14px 16px", margin: "12px 0 0"
		};
		const ROW = { display: "flex", flexDirection: "column", gap: 12, margin: 0 };
		const SLIDER = {
			width: "100%", margin: "10px 0 0", cursor: "pointer",
			accentColor: "var(--dsw-alias-button-primary-fill)"
		};
		const SLIDER_MARKS = {
			display: "flex", justifyContent: "space-between", fontSize: 11,
			color: "var(--dsw-alias-label-tertiary)", margin: "4px 0 0"
		};

		function Field(props) {
			return React.createElement("input", {
				type: "password",
				placeholder: props.placeholder,
				value: props.value,
				disabled: props.disabled,
				onChange: (event) => props.onChange(event.target.value),
				style: FIELD
			});
		}
		function Button(props) {
			return React.createElement("button", {
				type: "button",
				disabled: props.disabled,
				onClick: props.onClick,
				style: { ...BUTTON, opacity: props.disabled ? 0.5 : 1 }
			}, props.children);
		}

		const TICKET_KEY = "dsh-encrypt-remember";
		function storedTicket() {
			try {
				return typeof localStorage === "undefined" ? null : localStorage.getItem(TICKET_KEY);
			} catch {
				return null;
			}
		}
		function storeTicket(ticket) {
			try {
				if (typeof localStorage === "undefined") return;
				if (typeof ticket === "string" && ticket.length > 0) localStorage.setItem(TICKET_KEY, ticket);
				else localStorage.removeItem(TICKET_KEY);
			} catch {}
		}
		/**
		 * The single same-origin transport for every password operation. The
		 * paths are the exact routes the host's `dsh-encrypt/web` row registers
		 * on this page's own origin — no third-party endpoint is ever contacted
		 * from this bundle, and the raw password never leaves this page: only
		 * its SHA3-256 digest crosses in a POST body.
		 *
		 * The remembered-login ticket normally travels as the HttpOnly
		 * cookie only. Deployments that opt into rememberChannel "header"
		 * additionally carry it as an explicit `x-dsh-encrypt-remember`
		 * header (localStorage-backed, for cookie-storage-quirky WebViews);
		 * that channel is off by default because it makes the ticket
		 * readable to any script on this page.
		 */
		function apiPostRaw(path, payload) {
			const headers = { "content-type": "application/json" };
			const ticket = storedTicket();
			if (ticket !== null) headers["x-dsh-encrypt-remember"] = ticket;
			return fetch(path, {
				method: "POST",
				headers,
				body: JSON.stringify(payload ?? {})
			}).then(async (response) => {
				return await response.json();
			});
		}
		function apiPost(path, payload) {
			return apiPostRaw(path, payload).then((body) => {
				if (!body.ok) throw new Error(body.message || body.code);
				return body.value;
			});
		}
		/**
		 * Persist or drop the remembered ticket after a mutation response.
		 * The cookie channel (default) keeps no localStorage copy at all and
		 * purges any legacy one; only rememberChannel "header" stores tickets.
		 */
		function syncTicket(body) {
			if (body?.ok !== true) return;
			const value = body.value ?? {};
			if (value.rememberChannel !== "header") {
				storeTicket(null);
				return;
			}
			if (typeof value.ticket === "string" && value.ticket.length > 0) storeTicket(value.ticket);
			else if (value.remembered === false) storeTicket(null);
		}

		// ── auto-unlock when the WebUI opens ─────────────────────────────────
		// The remembered login only applies to localhost and is triggered by
		// opening the WebUI: the bundle pings the status route (which unlocks
		// the store from the stored ticket) as soon as the page loads.
		function pingStatus() {
			void apiPostRaw("/api/credentials.status").then((body) => {
				if (body?.ok !== true) return;
				if (body.value?.ticketRejected || body.value?.rememberChannel !== "header") storeTicket(null);
			}).catch(() => {});
		}
		if (typeof window !== "undefined" && typeof document !== "undefined" && typeof fetch === "function") {
			pingStatus();
			if (document.readyState !== "complete") window.addEventListener("load", () => pingStatus(), { once: true });
		}

		// ── remembered-login slider mapping ─────────────────────────────────
		const SLIDER_MAX = 31;
		function sliderFromDays(days) {
			if (days === -1) return SLIDER_MAX;
			return typeof days === "number" && Number.isFinite(days) ? Math.max(0, Math.min(SLIDER_MAX - 1, days)) : 0;
		}
		function daysFromSlider(value) {
			return value === SLIDER_MAX ? -1 : value;
		}
		function rememberLabel(value) {
			if (value === 0) return "每次都输入密码";
			if (value === SLIDER_MAX) return "永远免密登录（仅本机）";
			return `${value} 天内免密登录（仅本机）`;
		}
		function expiryText(ms) {
			const date = new Date(ms);
			if (Number.isNaN(date.getTime())) return "";
			return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
		}

		function EncryptionSection(_props) {
			const [status, setStatus] = React.useState(void 0);
			const [busy, setBusy] = React.useState(false);
			const [failure, setFailure] = React.useState(void 0);
			const [notice, setNotice] = React.useState(void 0);
			const [first, setFirst] = React.useState("");
			const [second, setSecond] = React.useState("");
			const [unlockPw, setUnlockPw] = React.useState("");
			const [oldPw, setOldPw] = React.useState("");
			const [slider, setSlider] = React.useState(0);

			const refresh = React.useCallback(async () => {
				try {
					const body = await apiPostRaw("/api/credentials.status");
					if (!body.ok) throw new Error(body.message || body.code);
					if (body.value?.ticketRejected || body.value?.rememberChannel !== "header") storeTicket(null);
					setStatus(body.value);
					setSlider(sliderFromDays(body.value.remember?.days));
					setFailure(void 0);
				} catch (error) {
					setFailure(error instanceof Error ? error.message : String(error));
				}
			}, []);
			React.useEffect(() => {
				void refresh();
			}, [refresh]);

			const run = async (path, payload, done) => {
				setBusy(true);
				setFailure(void 0);
				setNotice(void 0);
				try {
					const body = await apiPostRaw(path, payload);
					if (!body.ok) throw new Error(body.message || body.code);
					syncTicket(body);
					setFirst("");
					setSecond("");
					setUnlockPw("");
					setOldPw("");
					await refresh();
					if (done !== void 0) setNotice(done);
				} catch (error) {
					setFailure(error instanceof Error ? error.message : String(error));
				} finally {
					setBusy(false);
				}
			};

			const saveSlider = async (raw) => {
				setBusy(true);
				setFailure(void 0);
				try {
					const body = await apiPostRaw("/api/credentials.config", { action: "set", rememberDays: daysFromSlider(Number(raw)) });
					if (!body.ok) throw new Error(body.message || body.code);
					syncTicket(body);
					await refresh();
				} catch (error) {
					setFailure(error instanceof Error ? error.message : String(error));
				} finally {
					setBusy(false);
				}
			};

			const doublePassword = first.length > 0 && first === second && first.length >= 8;
			const passwordHint = first.length > 0 && first.length < 8 ? "密码至少 8 个字符" : first.length > 0 && second.length > 0 && first !== second ? "两次输入的密码不一致" : void 0;

			if (status === void 0) {
				return React.createElement("p", { style: HINT }, "读取加密状态…");
			}
			const { format, unlocked, local, remember, lockout } = status;
			const lockSeconds = lockout?.retryAfterMs > 0 ? Math.max(1, Math.ceil(lockout.retryAfterMs / 1000)) : 0;

			const localBanner = !local ? React.createElement("p", { key: "nl", style: WARN }, "当前不是本机访问：必须每次输入密码解锁，且不能设置、修改或移除密码。") : null;

			const sliderCard = React.createElement("div", { key: "slider", style: CARD }, [
				React.createElement("p", { key: "t", style: LABEL }, "免密登录时长（仅本机生效）"),
				React.createElement("input", {
					key: "s",
					type: "range",
					min: 0,
					max: SLIDER_MAX,
					step: 1,
					value: slider,
					disabled: busy || !local,
					onChange: (event) => setSlider(Number(event.currentTarget.value)),
					onPointerUp: (event) => void saveSlider(event.currentTarget.value),
					onKeyUp: (event) => {
						if (["ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown"].includes(event.key)) void saveSlider(event.currentTarget.value);
					},
					style: { ...SLIDER, opacity: !local ? 0.5 : 1 }
				}),
				React.createElement("p", { key: "v", style: LABEL }, rememberLabel(slider)),
				React.createElement("div", { key: "m", style: SLIDER_MARKS }, [
					React.createElement("span", { key: "a" }, "每次"),
					React.createElement("span", { key: "e" }, "永远")
				]),
				!local ? React.createElement("p", { key: "n", style: HINT }, "非本机访问始终需要输入密码。") :
					remember?.active ? React.createElement("p", { key: "n", style: OK }, remember.expiresAt !== null ? `免密登录生效中，到期时间：${expiryText(remember.expiresAt)}` : "免密登录生效中，永不过期。") :
					React.createElement("p", { key: "n", style: HINT }, format === "plain" ? "设置加密密码后生效：按滑块时长在本机签发免密票据。" : "解锁后按滑块时长在本机签发免密票据。")
			]);

			if (format === "plain") {
				return React.createElement("div", { style: ROW }, [
					localBanner,
					status.plaintextForbidden ? React.createElement("p", { key: "forbidden", style: WARN }, "警告：凭证文件被人替换成了明文，而密文策略已生效——凭证解析已暂停。请在下方重新设置加密密码，文件将立即恢复为密文。") : null,
					React.createElement("p", { key: "intro", style: LABEL }, "当前凭证以明文存储在 .credentials.yaml 中。设置密码后，同一文件的内容会被替换为 AES-256-GCM 密文（SHA3-256 完整性校验），每次模型调用时临时解密。"),
					local ? React.createElement("div", { key: "card", style: CARD }, [
						React.createElement("p", { key: "t", style: LABEL }, "设置加密密码"),
						React.createElement(Field, { key: "f1", placeholder: "新密码（至少 8 个字符）", value: first, disabled: busy, onChange: setFirst }),
						React.createElement(Field, { key: "f2", placeholder: "再次输入新密码", value: second, disabled: busy, onChange: setSecond }),
						passwordHint !== void 0 ? React.createElement("p", { key: "h", style: WARN }, passwordHint) : null,
						React.createElement(Button, { key: "b", disabled: busy || !doublePassword, onClick: () => void run("/api/credentials.set-password", { digest: sha3_256Hex(first) }, "密码已设置，凭证已加密保存") }, "加密并保存"),
						React.createElement("p", { key: "n", style: HINT }, "设置后重启 dsh 需要重新输入密码解锁（本设置页即是解锁入口）。忘记密码只能清除凭证重新配置。")
					]) : null,
					sliderCard,
					failure !== void 0 ? React.createElement("p", { key: "err", style: WARN }, failure) : null,
					notice !== void 0 ? React.createElement("p", { key: "ok", style: OK }, notice) : null
				]);
			}
			if (!unlocked) {
				return React.createElement("div", { style: ROW }, [
					localBanner,
					lockSeconds > 0 ? React.createElement("p", { key: "lockout", style: WARN }, "解锁尝试次数过多，已临时锁定：请在 " + lockSeconds + " 秒后重试（连续失败会自动延长锁定时间）。") : null,
					React.createElement("p", { key: "intro", style: WARN }, "凭证库已加密但处于锁定状态——模型调用暂时不可用。输入密码解锁后立即恢复。"),
					React.createElement("div", { key: "card", style: CARD }, [
						React.createElement(Field, { key: "f", placeholder: "凭证库密码", value: unlockPw, disabled: busy || lockSeconds > 0, onChange: setUnlockPw }),
						React.createElement(Button, { key: "b", disabled: busy || unlockPw.length === 0 || lockSeconds > 0, onClick: () => void run("/api/credentials.unlock", { digest: sha3_256Hex(unlockPw) }, "已解锁") }, "解锁")
					]),
					sliderCard,
					failure !== void 0 ? React.createElement("p", { key: "err", style: WARN }, failure) : null,
					notice !== void 0 ? React.createElement("p", { key: "ok", style: OK }, notice) : null
				]);
			}
			return React.createElement("div", { style: ROW }, [
				localBanner,
				React.createElement("p", { key: "intro", style: OK }, "凭证已加密且当前进程已解锁。"),
				local ? React.createElement("div", { key: "card", style: CARD }, [
					React.createElement("p", { key: "t", style: LABEL }, "修改密码"),
					React.createElement(Field, { key: "f0", placeholder: "当前密码", value: oldPw, disabled: busy, onChange: setOldPw }),
					React.createElement(Field, { key: "f1", placeholder: "新密码（至少 8 个字符）", value: first, disabled: busy, onChange: setFirst }),
					React.createElement(Field, { key: "f2", placeholder: "再次输入新密码", value: second, disabled: busy, onChange: setSecond }),
					passwordHint !== void 0 ? React.createElement("p", { key: "h", style: WARN }, passwordHint) : null,
					React.createElement(Button, { key: "b", disabled: busy || !doublePassword || oldPw.length === 0, onClick: () => void run("/api/credentials.change-password", { digest: sha3_256Hex(first), oldDigest: sha3_256Hex(oldPw) }, "密码已修改") }, "修改密码")
				]) : null,
				sliderCard,
				failure !== void 0 ? React.createElement("p", { key: "err", style: WARN }, failure) : null,
				notice !== void 0 ? React.createElement("p", { key: "ok", style: OK }, notice) : null
			]);
		}
		//#endregion
		const inject = [
			"slots"
		];
		function apply(ctx) {
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "encryption",
				order: 1,
				label: () => "加密安全"
			}, EncryptionSection));
		}
		exports.apply = apply;
		exports.inject = inject;
		exports.digestPassword = sha3_256Hex;
		return module.exports;
	}
});
