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
		 * row registers; the password only ever crosses once, in a POST body.
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

		/**
		 * The single same-origin transport for every password operation. The
		 * paths are the exact routes the host's `dsh-encrypt/web` row registers
		 * on this page's own origin — no third-party endpoint is ever contacted
		 * from this bundle, and the password crosses this one POST body only.
		 */
		function apiPost(path, payload) {
			return fetch(path, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(payload ?? {})
			}).then(async (response) => {
				const body = await response.json();
				if (!body.ok) throw new Error(body.message || body.code);
				return body.value;
			});
		}

		function EncryptionSection(_props) {
			const [status, setStatus] = React.useState(void 0);
			const [busy, setBusy] = React.useState(false);
			const [failure, setFailure] = React.useState(void 0);
			const [notice, setNotice] = React.useState(void 0);
			const [first, setFirst] = React.useState("");
			const [second, setSecond] = React.useState("");
			const [unlockPw, setUnlockPw] = React.useState("");

			const refresh = React.useCallback(async () => {
				try {
					setStatus(await apiPost("/api/credentials.status"));
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
					await apiPost(path, payload);
					setFirst("");
					setSecond("");
					setUnlockPw("");
					await refresh();
					if (done !== void 0) setNotice(done);
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
			const { format, unlocked } = status;

			if (format === "plain") {
				return React.createElement("div", { style: ROW }, [
					React.createElement("p", { key: "intro", style: LABEL }, "当前凭证以明文存储在 .credentials.yaml 中。设置密码后，同一文件的内容会被替换为 AES-256-GCM 密文（SHA3-256 完整性校验），每次模型调用时临时解密。"),
					React.createElement("div", { key: "card", style: CARD }, [
						React.createElement("p", { key: "t", style: LABEL }, "设置加密密码"),
						React.createElement(Field, { key: "f1", placeholder: "新密码（至少 8 个字符）", value: first, disabled: busy, onChange: setFirst }),
						React.createElement(Field, { key: "f2", placeholder: "再次输入新密码", value: second, disabled: busy, onChange: setSecond }),
						passwordHint !== void 0 ? React.createElement("p", { key: "h", style: WARN }, passwordHint) : null,
						React.createElement(Button, { key: "b", disabled: busy || !doublePassword, onClick: () => void run("/api/credentials.set-password", { password: first }, "密码已设置，凭证已加密保存") }, "加密并保存"),
						React.createElement("p", { key: "n", style: HINT }, "设置后重启 dsh 需要重新输入密码解锁（本设置页即是解锁入口）。忘记密码只能清除凭证重新配置。")
					]),
					failure !== void 0 ? React.createElement("p", { key: "err", style: WARN }, failure) : null,
					notice !== void 0 ? React.createElement("p", { key: "ok", style: OK }, notice) : null
				]);
			}
			if (!unlocked) {
				return React.createElement("div", { style: ROW }, [
					React.createElement("p", { key: "intro", style: WARN }, "凭证库已加密但处于锁定状态——模型调用暂时不可用。输入密码解锁后立即恢复。"),
					React.createElement("div", { key: "card", style: CARD }, [
						React.createElement(Field, { key: "f", placeholder: "凭证库密码", value: unlockPw, disabled: busy, onChange: setUnlockPw }),
						React.createElement(Button, { key: "b", disabled: busy || unlockPw.length === 0, onClick: () => void run("/api/credentials.unlock", { password: unlockPw }, "已解锁") }, "解锁")
					]),
					failure !== void 0 ? React.createElement("p", { key: "err", style: WARN }, failure) : null,
					notice !== void 0 ? React.createElement("p", { key: "ok", style: OK }, notice) : null
				]);
			}
			return React.createElement("div", { style: ROW }, [
				React.createElement("p", { key: "intro", style: OK }, "凭证已加密且当前进程已解锁。"),
				React.createElement("div", { key: "card", style: CARD }, [
					React.createElement("p", { key: "t", style: LABEL }, "修改密码"),
					React.createElement(Field, { key: "f1", placeholder: "新密码（至少 8 个字符）", value: first, disabled: busy, onChange: setFirst }),
					React.createElement(Field, { key: "f2", placeholder: "再次输入新密码", value: second, disabled: busy, onChange: setSecond }),
					passwordHint !== void 0 ? React.createElement("p", { key: "h", style: WARN }, passwordHint) : null,
					React.createElement(Button, { key: "b", disabled: busy || !doublePassword, onClick: () => void run("/api/credentials.change-password", { password: first }, "密码已修改") }, "修改密码")
				]),
				React.createElement("div", { key: "card2", style: CARD }, [
					React.createElement("p", { key: "t", style: LABEL }, "移除密码"),
					React.createElement("p", { key: "h", style: HINT }, "解密全部凭证并恢复为明文存储。仅在你不再需要加密保护时使用。"),
					React.createElement(Button, { key: "b", disabled: busy, onClick: () => {
						if (window.confirm("确定移除密码并恢复明文存储吗？")) void run("/api/credentials.clear-password", {}, "密码已移除，凭证恢复明文存储");
					} }, "移除密码")
				]),
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
		return module.exports;
	}
});
