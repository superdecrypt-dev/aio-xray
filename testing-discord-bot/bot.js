const fs = require("fs");
const net = require("net");
const path = require("path");
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
  AttachmentBuilder,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle
} = require("discord.js");

const TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const ADMIN_ROLE_ID = process.env.DISCORD_ADMIN_ROLE_ID;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;

const SOCK_PATH = "/run/xray-backend.sock";
const BACKEND_TIMEOUT_MS = 8000;

// For /ping & /status: try direct reply first to avoid ephemeral editReply rendering glitch on mobile
const QUICK_REPLY_MS = 1200;

if (!TOKEN || !GUILD_ID || !ADMIN_ROLE_ID || !CLIENT_ID) {
  console.error("Missing env vars: DISCORD_BOT_TOKEN / DISCORD_GUILD_ID / DISCORD_ADMIN_ROLE_ID / DISCORD_CLIENT_ID");
  process.exit(1);
}

function isAdmin(member) {
  return member.roles.cache.has(String(ADMIN_ROLE_ID));
}

function mapBackendError(err) {
  const code = err && err.code ? String(err.code) : "";
  if (code === "ENOENT") {
    return "Backend socket not found. Pastikan xray-backend aktif dan socket ada di /run/xray-backend.sock";
  }
  if (code === "ECONNREFUSED") {
    return "Backend connection refused. Pastikan xray-backend sedang running.";
  }
  if (code === "ETIMEDOUT") {
    return "Backend timeout. Cek beban server atau log xray-backend.";
  }
  return err && err.message ? err.message : "Unknown backend error";
}

function badge(state) {
  const s = String(state || "unknown").toLowerCase().trim();
  if (s === "active") return "🟢 active";
  if (s === "inactive") return "🟡 inactive";
  if (s === "failed") return "🔴 failed";
  return `⚪ ${state || "unknown"}`;
}

function callBackend(req) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(SOCK_PATH);
    let buf = "";
    let done = false;

    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      const e = new Error("Backend timeout");
      e.code = "ETIMEDOUT";
      try { client.destroy(e); } catch (_) {}
      reject(e);
    }, BACKEND_TIMEOUT_MS);

    const finishReject = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(err);
    };

    const finishResolve = (obj) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(obj);
    };

    client.on("connect", () => {
      try {
        client.write(JSON.stringify(req) + "\n");
      } catch (e) {
        finishReject(e);
      }
    });

    client.on("data", (data) => {
      buf += data.toString("utf8");
      const idx = buf.indexOf("\n");
      if (idx !== -1) {
        client.end();
        const line = buf.slice(0, idx);
        try {
          finishResolve(JSON.parse(line));
        } catch (_) {
          finishReject(new Error("Invalid JSON response from backend"));
        }
      }
    });

    client.on("error", finishReject);

    client.on("close", () => {
      if (!done && buf.length > 0 && !buf.includes("\n")) {
        finishReject(new Error("Backend closed connection before sending a full response"));
      }
    });
  });
}

function lightValidate(protocol, username, days, quota_gb) {
  protocol = String(protocol || "").toLowerCase().trim();
  const okProto = ["vless", "vmess", "trojan", "allproto"].includes(protocol);
  if (!okProto) return { ok: false, msg: "protocol invalid" };
  if (!/^[A-Za-z0-9_]+$/.test(username || "")) return { ok: false, msg: "username invalid" };
  if (days !== undefined) {
    if (!Number.isInteger(days) || days < 1 || days > 3650) return { ok: false, msg: "days out of range (1..3650)" };
  }
  if (quota_gb !== undefined) {
    if (typeof quota_gb !== "number" || quota_gb < 0) return { ok: false, msg: "quota_gb must be >= 0" };
  }
  return { ok: true, protocol };
}

function buildDetailTxtPath(proto, finalEmail) {
  const m = /^([A-Za-z0-9_]+)@(vless|vmess|trojan|allproto)$/.exec(finalEmail || "");
  if (!m) return null;

  const suffix = m[2];
  if (suffix !== proto) return null;

  const baseDir = proto === "allproto" ? "/opt/allproto" : `/opt/${proto}`;
  return path.join(baseDir, `${finalEmail}.txt`);
}

function buildPingPayload(wsMs, ipcMs) {
  const embed = new EmbedBuilder()
    .setTitle("🏓 Pong")
    .addFields(
      { name: "Bot", value: "🟢 OK", inline: true },
      { name: "Discord WS", value: `${wsMs} ms`, inline: true },
      { name: "Backend IPC", value: `${ipcMs} ms`, inline: true },
    )
    .setFooter({ text: "Latency = round-trip IPC ke backend." });

  // Important: include plain content summary to avoid “embed sometimes fades/vanishes” on mobile
  const content =
    `🏓 Pong\n` +
    `Discord WS: ${wsMs} ms\n` +
    `Backend IPC: ${ipcMs} ms`;

  return { content, embeds: [embed], ephemeral: true };
}

function buildStatusPayload(xrayState, nginxState, ipcMs) {
  const xray = badge(xrayState);
  const nginx = badge(nginxState);

  const embed = new EmbedBuilder()
    .setTitle("🧩 Service Status")
    .addFields(
      { name: "Xray", value: xray, inline: true },
      { name: "Nginx", value: nginx, inline: true },
      { name: "Backend IPC", value: `${ipcMs} ms`, inline: true }
    )
    .setFooter({ text: "Status diambil oleh backend via systemctl is-active." });

  const content =
    `🧩 Service Status\n` +
    `Xray : ${xray}\n` +
    `Nginx: ${nginx}\n` +
    `IPC  : ${ipcMs} ms`;

  return { content, embeds: [embed], ephemeral: true };
}

async function registerCommands() {
  const commands = [
    new SlashCommandBuilder().setName("help").setDescription("Cara pakai bot & penjelasan fungsi"),
    new SlashCommandBuilder().setName("ping").setDescription("Health check bot + backend latency (ms)"),
    new SlashCommandBuilder().setName("status").setDescription("Status service Xray dan Nginx (admin only)"),
    new SlashCommandBuilder()
      .setName("add")
      .setDescription("Create Xray user (via Python backend)")
      .addStringOption(o => o.setName("protocol").setDescription("vless/vmess/trojan/allproto").setRequired(true))
      .addStringOption(o => o.setName("username").setDescription("username tanpa suffix [a-zA-Z0-9_]").setRequired(true))
      .addIntegerOption(o => o.setName("days").setDescription("masa aktif (hari)").setRequired(true))
      .addNumberOption(o => o.setName("quota_gb").setDescription("quota (GB), 0=unlimited").setRequired(true)),
    new SlashCommandBuilder()
      .setName("del")
      .setDescription("Delete Xray user (via Python backend) + confirm button")
      .addStringOption(o => o.setName("protocol").setDescription("vless/vmess/trojan/allproto").setRequired(true))
      .addStringOption(o => o.setName("username").setDescription("username tanpa suffix [a-zA-Z0-9_]").setRequired(true)),
  ].map(c => c.toJSON());

  const rest = new REST({ version: "10" }).setToken(TOKEN);
  await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once("ready", () => {
  console.log(`Logged in as ${client.user.tag}`);
});

client.on("interactionCreate", async (interaction) => {
  // --------------------
  // BUTTONS
  // --------------------
  if (interaction.isButton()) {
    try {
      if (String(interaction.guildId) !== String(GUILD_ID)) {
        return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
      }
      if (!isAdmin(interaction.member)) {
        return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
      }

      const customId = String(interaction.customId || "");

      // detail:<proto>:<finalEmail>
      if (customId.startsWith("detail:")) {
        const parts = customId.split(":");
        if (parts.length !== 3) return interaction.reply({ content: "❌ Invalid button", ephemeral: true });

        const proto = String(parts[1] || "").toLowerCase().trim();
        const finalEmail = String(parts[2] || "").trim();
        if (!["vless", "vmess", "trojan", "allproto"].includes(proto)) {
          return interaction.reply({ content: "❌ Invalid protocol", ephemeral: true });
        }

        const p = buildDetailTxtPath(proto, finalEmail);
        if (!p) return interaction.reply({ content: "❌ Invalid target", ephemeral: true });

        await interaction.deferReply({ ephemeral: true });

        if (!fs.existsSync(p)) return interaction.editReply(`❌ File not found: ${p}`);

        const file = new AttachmentBuilder(p, { name: path.basename(p) });
        const embed = new EmbedBuilder()
          .setTitle("📄 XRAY ACCOUNT DETAIL")
          .addFields(
            { name: "Protocol", value: proto, inline: true },
            { name: "Username", value: finalEmail, inline: true }
          )
          .setFooter({ text: "Resent detail file (.txt)" });

        return interaction.editReply({ embeds: [embed], files: [file] });
      }

      // delconfirm:<proto>:<username>  / delcancel:<proto>:<username>
      if (customId.startsWith("delconfirm:") || customId.startsWith("delcancel:")) {
        const parts = customId.split(":");
        if (parts.length !== 3) return interaction.reply({ content: "❌ Invalid button", ephemeral: true });

        const action = parts[0];
        const proto = String(parts[1] || "").toLowerCase().trim();
        const username = String(parts[2] || "").trim();

        const v = lightValidate(proto, username);
        if (!v.ok) return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });

        if (action === "delcancel") {
          return interaction.update({ content: "✅ Delete cancelled.", embeds: [], components: [] });
        }

        await interaction.deferUpdate();

        const resp = await callBackend({ action: "del", protocol: proto, username });
        if (resp.status !== "ok") {
          return interaction.editReply({ content: `❌ Failed: ${resp.error || "unknown error"}`, embeds: [], components: [] });
        }

        const embed = new EmbedBuilder()
          .setTitle("✅ XRAY Account Deleted")
          .addFields(
            { name: "Protocol", value: proto, inline: true },
            { name: "Username", value: resp.username || "-", inline: true },
            { name: "Removed", value: String(resp.removed || "?"), inline: true }
          );

        return interaction.editReply({ content: null, embeds: [embed], components: [] });
      }

      return interaction.reply({ content: "❌ Unknown button", ephemeral: true });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ Error: ${msg}`);
      return interaction.reply({ content: `❌ Error: ${msg}`, ephemeral: true });
    }
  }

  // --------------------
  // SLASH COMMANDS
  // --------------------
  if (!interaction.isChatInputCommand()) return;

  if (String(interaction.guildId) !== String(GUILD_ID)) {
    return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
  }

  const cmd = interaction.commandName;

  // /help is read-only, open to guild members
  if (cmd === "help") {
    const embed = new EmbedBuilder()
      .setTitle("📘 XRAY Discord Bot Help")
      .setDescription("Bot ini untuk manajemen akun Xray via backend service (IPC).")
      .addFields(
        { name: "/add", value: "Membuat akun Xray + mengirim detail (.txt). **Admin only**", inline: false },
        { name: "/del", value: "Menghapus akun Xray (dengan tombol konfirmasi). **Admin only**", inline: false },
        { name: "/ping", value: "Cek bot hidup + latency backend (ms).", inline: false },
        { name: "/status", value: "Lihat status service Xray & Nginx. **Admin only**", inline: false },
        { name: "Aturan username", value: "`[A-Za-z0-9_]` (tanpa suffix). Bot akan menambahkan `@vless/@vmess/@trojan/@allproto`.", inline: false },
        { name: "Quota", value: "`quota_gb=0` berarti Unlimited.", inline: false }
      )
      .setFooter({ text: "Tip: Jika error socket/backend, cek /status (admin) atau journalctl xray-backend." });

    return interaction.reply({ embeds: [embed], ephemeral: true });
  }

  // /ping is read-only, open to guild members
  if (cmd === "ping") {
    try {
      const wsMs = Math.round(client.ws.ping);
      const t0 = Date.now();
      const work = callBackend({ action: "ping" });

      // Try to finish quickly to avoid defer+edit (mobile glitch)
      const quick = await Promise.race([
        work.then((r) => ({ ok: true, r })),
        new Promise((res) => setTimeout(() => res(null), QUICK_REPLY_MS)),
      ]);

      if (quick) {
        if (!quick.ok || quick.r.status !== "ok") {
          const err = quick && quick.ok === false ? quick.e : null;
          const msg = err ? mapBackendError(err) : (quick.r.error || "unknown error");
          return interaction.reply({ content: `❌ Backend ping failed: ${msg}`, ephemeral: true });
        }
        const ipcMs = Date.now() - t0;
        return interaction.reply(buildPingPayload(wsMs, ipcMs));
      }

      // Fallback: defer then edit
      await interaction.deferReply({ ephemeral: true });
      const resp = await work;
      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Backend ping failed: ${resp.error || "unknown error"}`);
      }
      const ipcMs = Date.now() - t0;
      const payload = buildPingPayload(wsMs, ipcMs);
      return interaction.editReply({ content: payload.content, embeds: payload.embeds });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      // safe reply/edit depending on state
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // Admin-only commands below
  if (!isAdmin(interaction.member)) {
    return interaction.reply({ content: "❌ Unauthorized (admin role required).", ephemeral: true });
  }

  // /status (admin-only)
  if (cmd === "status") {
    try {
      const t0 = Date.now();
      const work = callBackend({ action: "status" });

      const quick = await Promise.race([
        work.then((r) => ({ ok: true, r })),
        new Promise((res) => setTimeout(() => res(null), QUICK_REPLY_MS)),
      ]);

      if (quick) {
        if (!quick.ok || quick.r.status !== "ok") {
          const err = quick && quick.ok === false ? quick.e : null;
          const msg = err ? mapBackendError(err) : (quick.r.error || "unknown error");
          return interaction.reply({ content: `❌ Failed: ${msg}`, ephemeral: true });
        }
        const ipcMs = Date.now() - t0;
        return interaction.reply(buildStatusPayload(quick.r.xray, quick.r.nginx, ipcMs));
      }

      await interaction.deferReply({ ephemeral: true });
      const resp = await work;
      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Failed: ${resp.error || "unknown error"}`);
      }
      const ipcMs = Date.now() - t0;
      const payload = buildStatusPayload(resp.xray, resp.nginx, ipcMs);
      return interaction.editReply({ content: payload.content, embeds: payload.embeds });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // /add (admin-only)
  if (cmd === "add") {
    try {
      const protocolRaw = interaction.options.getString("protocol", true);
      const username = interaction.options.getString("username", true);
      const days = interaction.options.getInteger("days", true);
      const quota_gb = interaction.options.getNumber("quota_gb", true);

      const v = lightValidate(protocolRaw, username, days, quota_gb);
      if (!v.ok) return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });

      await interaction.deferReply({ ephemeral: true });
      const resp = await callBackend({ action: "add", protocol: v.protocol, username, days, quota_gb });

      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Failed: ${resp.error || "unknown error"}`);
      }

      const finalEmail = resp.username;
      const txtPath = resp.detail_path;

      const embed = new EmbedBuilder()
        .setTitle("✅ XRAY Account Created")
        .addFields(
          { name: "Protocol", value: v.protocol, inline: true },
          { name: "Username", value: finalEmail, inline: true },
          { name: "Valid Until", value: resp.expired_at || "-", inline: true },
          { name: "Days", value: String(days), inline: true },
          { name: "Quota (GB)", value: String(quota_gb), inline: true }
        )
        .setFooter({ text: "Attached: XRAY ACCOUNT DETAIL (.txt)" });

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId(`detail:${v.protocol}:${finalEmail}`)
          .setLabel("Resend Detail TXT")
          .setStyle(ButtonStyle.Secondary)
          .setEmoji("📄")
      );

      let files = [];
      if (txtPath && typeof txtPath === "string" && txtPath.endsWith(".txt") && fs.existsSync(txtPath)) {
        files = [new AttachmentBuilder(txtPath, { name: path.basename(txtPath) })];
      }

      return interaction.editReply({ embeds: [embed], components: [row], files });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // /del (admin-only) confirm button
  if (cmd === "del") {
    const protocolRaw = interaction.options.getString("protocol", true);
    const username = interaction.options.getString("username", true);

    const v = lightValidate(protocolRaw, username);
    if (!v.ok) return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });

    const finalEmail = `${username}@${v.protocol}`;

    const embed = new EmbedBuilder()
      .setTitle("⚠️ Confirm Delete")
      .setDescription("Klik **Confirm** untuk menghapus akun ini. Aksi tidak bisa dibatalkan.")
      .addFields(
        { name: "Protocol", value: v.protocol, inline: true },
        { name: "Username", value: finalEmail, inline: true }
      )
      .setFooter({ text: "Safety: delete membutuhkan konfirmasi." });

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId(`delconfirm:${v.protocol}:${username}`)
        .setLabel("Confirm Delete")
        .setStyle(ButtonStyle.Danger)
        .setEmoji("🗑️"),
      new ButtonBuilder()
        .setCustomId(`delcancel:${v.protocol}:${username}`)
        .setLabel("Cancel")
        .setStyle(ButtonStyle.Secondary)
        .setEmoji("✖️")
    );

    return interaction.reply({ embeds: [embed], components: [row], ephemeral: true });
  }
});

async function main() {
  await registerCommands();
  await client.login(TOKEN);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});