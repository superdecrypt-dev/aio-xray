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
  StringSelectMenuBuilder,
  ButtonBuilder,
  ButtonStyle,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
  ChannelSelectMenuBuilder,
  ChannelType,
} = require("discord.js");

const TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const ADMIN_ROLE_ID = process.env.DISCORD_ADMIN_ROLE_ID;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;

const SOCK_PATH = "/run/xray-backend.sock";
const BACKEND_TIMEOUT_MS = 8000;

// For /ping & /status: try direct reply first to avoid ephemeral editReply rendering glitch on mobile
const QUICK_REPLY_MS = 1200;

const PAGE_SIZE = 25; // Discord select menu max options
const ADD_PROTOCOLS = ["vless", "vmess", "trojan", "allproto"];
const LIST_PROTOCOLS = ["all", "vless", "vmess", "trojan", "allproto"];
const HELP_TABS = ["overview", "accounts", "add", "del", "ping", "status"];

// /notify state (persist)
const NOTIFY_STATE_PATH = "/opt/xray-discord-bot/state/notify.json";
const NOTIFY_MIN_INTERVAL_MIN = 5;
const NOTIFY_MAX_INTERVAL_MIN = 10080; // 7 days

let notifyCfg = {
  enabled: false,
  channel_id: null,
  interval_min: 60,
  last_run_at: null,   // ISO string
  last_error: null,    // string
};
let notifyTimer = null;

if (!TOKEN || !GUILD_ID || !ADMIN_ROLE_ID || !CLIENT_ID) {
  console.error("Missing env vars: DISCORD_BOT_TOKEN / DISCORD_GUILD_ID / DISCORD_ADMIN_ROLE_ID / DISCORD_CLIENT_ID");
  process.exit(1);
}

function isAdmin(member) {
  try {
    return member && member.roles && member.roles.cache && member.roles.cache.has(String(ADMIN_ROLE_ID));
  } catch (_) {
    return false;
  }
}

function mapBackendError(err) {
  if (!err) return "unknown error";
  if (typeof err === "string") return err;
  if (err.code === "ETIMEDOUT") return "backend timeout";
  if (err.code === "ENOENT") return "backend socket not found";
  return err.message || "unknown error";
}

function badge(state) {
  state = String(state || "").trim().toLowerCase();
  if (state === "active") return "🟢 active";
  if (state === "inactive") return "🔴 inactive";
  if (state === "failed") return "🔴 failed";
  return `⚪ ${state || "unknown"}`;
}

function clampInt(n, min, max) {
  n = Number.isFinite(n) ? Math.trunc(n) : min;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function safeMkdirp(dir, mode = 0o700) {
  try {
    fs.mkdirSync(dir, { recursive: true, mode });
    return true;
  } catch (_) {
    return false;
  }
}

function loadNotifyCfg() {
  try {
    if (!fs.existsSync(NOTIFY_STATE_PATH)) return;
    const raw = fs.readFileSync(NOTIFY_STATE_PATH, "utf8");
    const obj = JSON.parse(raw);

    notifyCfg.enabled = !!obj.enabled;
    notifyCfg.channel_id = obj.channel_id ? String(obj.channel_id) : null;

    const iv = Number(obj.interval_min);
    notifyCfg.interval_min = Number.isFinite(iv)
      ? clampInt(iv, NOTIFY_MIN_INTERVAL_MIN, NOTIFY_MAX_INTERVAL_MIN)
      : 60;

    notifyCfg.last_run_at = obj.last_run_at ? String(obj.last_run_at) : null;
    notifyCfg.last_error = obj.last_error ? String(obj.last_error) : null;
  } catch (e) {
    // keep defaults
  }
}

function saveNotifyCfg() {
  try {
    const dir = path.dirname(NOTIFY_STATE_PATH);
    if (!safeMkdirp(dir, 0o700)) return false;

    const tmp = `${NOTIFY_STATE_PATH}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(notifyCfg, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, NOTIFY_STATE_PATH);
    return true;
  } catch (_) {
    return false;
  }
}

function stopNotifyScheduler() {
  if (notifyTimer) clearInterval(notifyTimer);
  notifyTimer = null;
}

function canRunNotify() {
  return notifyCfg.enabled && notifyCfg.channel_id && notifyCfg.interval_min >= NOTIFY_MIN_INTERVAL_MIN;
}

function startNotifyScheduler(client) {
  stopNotifyScheduler();
  if (!canRunNotify()) return;

  const ms = notifyCfg.interval_min * 60 * 1000;
  notifyTimer = setInterval(() => {
    sendNotifyTick(client).catch(() => {});
  }, ms);
}

function buildNotifyMessageText({ wsMs, ipcMs, xrayState, nginxState, error }) {
  const ts = new Date().toISOString();
  const lines = [];
  lines.push("```");
  lines.push("🛎️ NOTIFIKASI XRAY (Berkala)");
  lines.push(`Waktu: ${ts}`);
  lines.push("");

  if (error) {
    lines.push("❌ ERROR");
    lines.push(String(error).slice(0, 900));
    lines.push("```");
    return lines.join("\n");
  }

  lines.push("🏓 Ping");
  lines.push(`Discord WS : ${wsMs} ms`);
  lines.push(`Backend IPC: ${ipcMs} ms`);
  lines.push("");
  lines.push("🧩 Status");
  lines.push(`Xray : ${badge(xrayState)}`);
  lines.push(`Nginx: ${badge(nginxState)}`);
  lines.push("```");
  return lines.join("\n");
}

async function sendNotifyTick(client) {
  if (!canRunNotify()) return;

  const channelId = String(notifyCfg.channel_id);
  const ch = await client.channels.fetch(channelId).catch(() => null);
  if (!ch || !ch.isTextBased()) {
    notifyCfg.last_error = `Channel invalid / not text-based: ${channelId}`;
    saveNotifyCfg();
    return;
  }

  const wsMs = Math.round(client.ws.ping);
  const t0 = Date.now();

  try {
    const pingResp = await callBackend({ action: "ping" });
    const statusResp = await callBackend({ action: "status" });
    const ipcMs = Date.now() - t0;

    if (!pingResp || pingResp.status !== "ok") {
      const msg = pingResp && pingResp.error ? pingResp.error : "backend ping failed";
      notifyCfg.last_error = msg;
      notifyCfg.last_run_at = new Date().toISOString();
      saveNotifyCfg();

      await ch.send({ content: buildNotifyMessageText({ wsMs, ipcMs, error: msg }) });
      return;
    }

    if (!statusResp || statusResp.status !== "ok") {
      const msg = statusResp && statusResp.error ? statusResp.error : "backend status failed";
      notifyCfg.last_error = msg;
      notifyCfg.last_run_at = new Date().toISOString();
      saveNotifyCfg();

      await ch.send({ content: buildNotifyMessageText({ wsMs, ipcMs, error: msg }) });
      return;
    }

    notifyCfg.last_error = null;
    notifyCfg.last_run_at = new Date().toISOString();
    saveNotifyCfg();

    await ch.send({
      content: buildNotifyMessageText({
        wsMs,
        ipcMs,
        xrayState: statusResp.xray,
        nginxState: statusResp.nginx
      })
    });
  } catch (e) {
    const msg = mapBackendError(e);
    notifyCfg.last_error = msg;
    notifyCfg.last_run_at = new Date().toISOString();
    saveNotifyCfg();
    try {
      await ch.send({ content: buildNotifyMessageText({ wsMs: Math.round(client.ws.ping), ipcMs: 0, error: msg }) });
    } catch (_) {}
  }
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
  const okProto = ADD_PROTOCOLS.includes(protocol);
  if (!okProto) return { ok: false, msg: "protocol invalid" };
  if (!/^[A-Za-z0-9_]+$/.test(username || "")) return { ok: false, msg: "username invalid" };
  if (days !== undefined) {
    if (!Number.isInteger(days) || days < 1 || days > 3650) return { ok: false, msg: "days out of range (1..3650)" };
  }
  if (quota_gb !== undefined) {
    if (typeof quota_gb !== "number" || !Number.isFinite(quota_gb) || quota_gb < 0) return { ok: false, msg: "quota_gb must be >= 0" };
  }
  return { ok: true, protocol };
}

function parseFinalEmail(finalEmail) {
  const m = /^([A-Za-z0-9_]+)@(vless|vmess|trojan|allproto)$/.exec(String(finalEmail || "").trim());
  if (!m) return null;
  return { base: m[1], proto: m[2], final: `${m[1]}@${m[2]}` };
}

function buildDetailTxtPath(proto, finalEmail) {
  const p = parseFinalEmail(finalEmail);
  if (!p) return null;
  if (p.proto !== proto) return null;
  const baseDir = proto === "allproto" ? "/opt/allproto" : `/opt/${proto}`;
  return path.join(baseDir, `${finalEmail}.txt`);
}

// /ping & /status content-only
function buildPingText(wsMs, ipcMs) {
  return (
    "```" +
    "\n🏓 Pong" +
    `\nDiscord WS : ${wsMs} ms` +
    `\nBackend IPC: ${ipcMs} ms` +
    "\n```"
  );
}

function buildStatusText(xrayState, nginxState, ipcMs) {
  const xray = badge(xrayState);
  const nginx = badge(nginxState);
  return (
    "```" +
    "\n🧩 Service Status" +
    `\nXray : ${xray}` +
    `\nNginx: ${nginx}` +
    `\nIPC  : ${ipcMs} ms` +
    "\n```"
  );
}

/**
 * ✅ TABLE only No & Username (for /accounts and /del list)
 */
function formatAccountsTable(items) {
  const header = "No  Username";
  const lines = [header];
  for (let i = 0; i < items.length; i++) {
    const it = items[i] || {};
    const no = String(i + 1).padEnd(3, " ");
    const user = String(it.username || "-").slice(0, 40);
    lines.push(`${no}${user}`);
  }
  return "```\n" + lines.join("\n") + "\n```";
}

/**
 * Row filter buttons (protocol filter):
 * - prefix: "acct" or "del"
 * - active: one of LIST_PROTOCOLS
 */
function buildProtocolFilterRow(prefix, active) {
  active = String(active || "all").toLowerCase().trim();
  if (!LIST_PROTOCOLS.includes(active)) active = "all";

  const mk = (proto, label, emoji) => {
    const isActive = active === proto;
    return new ButtonBuilder()
      .setCustomId(`filt:${prefix}:${proto}`)
      .setLabel(label)
      .setEmoji(emoji)
      .setStyle(isActive ? ButtonStyle.Primary : ButtonStyle.Secondary);
  };

  return new ActionRowBuilder().addComponents(
    mk("all", "ALL", "📌"),
    mk("vless", "VLESS", "🟦"),
    mk("vmess", "VMESS", "🟩"),
    mk("trojan", "TROJAN", "🟥"),
    mk("allproto", "ALLPROTO", "🟪"),
  );
}

/**
 * /notify panel UI
 */
function buildNotifyPanel({ extraRow } = {}) {
  const status = notifyCfg.enabled ? "🟢 ON" : "🔴 OFF";
  const ch = notifyCfg.channel_id ? `<#${notifyCfg.channel_id}>` : "`(belum diatur)`";
  const iv = `${notifyCfg.interval_min} menit`;
  const lastRun = notifyCfg.last_run_at ? `\`${notifyCfg.last_run_at}\`` : "`-`";
  const lastErr = notifyCfg.last_error ? `\`${String(notifyCfg.last_error).slice(0, 180)}\`` : "`-`";

  const embed = new EmbedBuilder()
    .setTitle("🛎️ Notify Panel")
    .setDescription(
      [
        "**Cara pakai:**",
        "1) Klik **Set Channel** → pilih channel notifikasi",
        "2) Klik **Set Interval** (menit)",
        "3) Klik **Enable/Disable** untuk toggle",
        "4) Klik **Test Now** untuk kirim 1x sekarang",
      ].join("\n")
    )
    .addFields(
      { name: "Status", value: status, inline: true },
      { name: "Channel", value: ch, inline: true },
      { name: "Interval", value: iv, inline: true },
      { name: "Last Run", value: lastRun, inline: false },
      { name: "Last Error", value: lastErr, inline: false },
    )
    .setFooter({ text: "Notifikasi berkala mengirim Ping + Status (text-only) ke channel target." });

  const toggleBtn = new ButtonBuilder()
    .setCustomId("notify:toggle")
    .setLabel(notifyCfg.enabled ? "Disable" : "Enable")
    .setStyle(notifyCfg.enabled ? ButtonStyle.Danger : ButtonStyle.Success)
    .setEmoji(notifyCfg.enabled ? "🛑" : "✅");

  const testBtn = new ButtonBuilder()
    .setCustomId("notify:test")
    .setLabel("Test Now")
    .setStyle(ButtonStyle.Secondary)
    .setEmoji("🧪");

  const refreshBtn = new ButtonBuilder()
    .setCustomId("notify:refresh")
    .setLabel("Refresh")
    .setStyle(ButtonStyle.Secondary)
    .setEmoji("🔄");

  const setChannelBtn = new ButtonBuilder()
    .setCustomId("notify:set_channel")
    .setLabel("Set Channel")
    .setStyle(ButtonStyle.Primary)
    .setEmoji("📌");

  const setIntervalBtn = new ButtonBuilder()
    .setCustomId("notify:set_interval")
    .setLabel("Set Interval")
    .setStyle(ButtonStyle.Primary)
    .setEmoji("⏱️");

  const row1 = new ActionRowBuilder().addComponents(toggleBtn, testBtn, refreshBtn);
  const row2 = new ActionRowBuilder().addComponents(setChannelBtn, setIntervalBtn);

  const components = [row1, row2];
  if (extraRow) components.splice(1, 0, extraRow); // insert between row1 and row2
  return { embeds: [embed], components };
}

function buildNotifyChannelSelectRow() {
  const menu = new ChannelSelectMenuBuilder()
    .setCustomId("notify:channel_select")
    .setPlaceholder("Pilih channel notifikasi…")
    .setMinValues(1)
    .setMaxValues(1)
    .setChannelTypes([ChannelType.GuildText, ChannelType.GuildAnnouncement]);

  return new ActionRowBuilder().addComponents(menu);
}

function buildNotifyIntervalModal() {
  const modal = new ModalBuilder()
    .setCustomId("notify:interval_modal")
    .setTitle("Set Interval Notifikasi (menit)");

  const minutesInput = new TextInputBuilder()
    .setCustomId("minutes")
    .setLabel(`Interval (menit) ${NOTIFY_MIN_INTERVAL_MIN}..${NOTIFY_MAX_INTERVAL_MIN}`)
    .setStyle(TextInputStyle.Short)
    .setRequired(true)
    .setPlaceholder("60");

  modal.addComponents(new ActionRowBuilder().addComponents(minutesInput));
  return modal;
}

async function buildListMessage(kind, protoFilter, offset) {
  // kind: "acct" or "del"
  const prefix = kind === "del" ? "del" : "acct";
  protoFilter = String(protoFilter || "all").toLowerCase().trim();
  if (!LIST_PROTOCOLS.includes(protoFilter)) protoFilter = "all";

  offset = clampInt(Number(offset || 0), 0, 10_000_000);

  const resp = await callBackend({
    action: "list",
    protocol: protoFilter,
    offset,
    limit: PAGE_SIZE
  });

  if (!resp || resp.status !== "ok") {
    const embed = new EmbedBuilder()
      .setTitle("❌ Failed")
      .setDescription(resp && resp.error ? String(resp.error) : "unknown error");
    return {
      embeds: [embed],
      components: [],
      ephemeral: true
    };
  }

  const items = Array.isArray(resp.items) ? resp.items : [];
  const total = Number.isFinite(resp.total) ? resp.total : items.length;
  const hasMore = !!resp.has_more;

  const title = kind === "del" ? "🗑️ Delete Accounts" : "📚 XRAY Accounts";

  const headerLine =
    kind === "del"
      ? "Pilih akun dari dropdown, lalu konfirmasi delete."
      : "Pilih akun dari dropdown untuk ambil ulang XRAY ACCOUNT DETAIL (.txt).";

  const tableBlock = items.length ? formatAccountsTable(items) : "_Tidak ada akun ditemukan._";

  const embed = new EmbedBuilder()
    .setTitle(title)
    .setDescription(`${headerLine}\n\n${tableBlock}`)
    .setFooter({ text: `Filter: ${protoFilter} | Showing ${items.length} of ${total} | Offset ${offset}` });

  // Components: Filter + (Dropdown) + Paging (Prev/Next only)
  const filterRow = buildProtocolFilterRow(prefix, protoFilter);

  const nav = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId(`${prefix}:prev:${protoFilter}:${offset}`)
      .setLabel("Prev")
      .setStyle(ButtonStyle.Secondary)
      .setEmoji("⬅️")
      .setDisabled(offset <= 0),
    new ButtonBuilder()
      .setCustomId(`${prefix}:next:${protoFilter}:${offset}`)
      .setLabel("Next")
      .setStyle(ButtonStyle.Secondary)
      .setEmoji("➡️")
      .setDisabled(!hasMore),
  );

  const components = [filterRow, nav];

  if (items.length > 0) {
    const placeholder = kind === "del"
      ? "Pilih akun yang ingin dihapus..."
      : "Pilih akun untuk ambil ulang XRAY ACCOUNT DETAIL (.txt)";

    const menu = new StringSelectMenuBuilder()
      .setCustomId(`${prefix}:sel:${protoFilter}:${offset}`)
      .setPlaceholder(placeholder)
      .addOptions(
        items.slice(0, PAGE_SIZE).map((it, idx) => {
          const u = String(it.username || "-");
          const p = String(it.protocol || "-");
          const e = String(it.expired_at || "-");
          return {
            label: `${idx + 1}. ${u}`.slice(0, 100),
            description: `${p} | exp ${e}`.slice(0, 100),
            value: u.slice(0, 100)
          };
        })
      );

    components.splice(1, 0, new ActionRowBuilder().addComponents(menu));
  }

  return { embeds: [embed], components, ephemeral: true };
}

function buildAddProtocolButtons() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId("addproto:vless").setLabel("VLESS").setStyle(ButtonStyle.Primary),
    new ButtonBuilder().setCustomId("addproto:vmess").setLabel("VMESS").setStyle(ButtonStyle.Primary),
    new ButtonBuilder().setCustomId("addproto:trojan").setLabel("TROJAN").setStyle(ButtonStyle.Primary),
    new ButtonBuilder().setCustomId("addproto:allproto").setLabel("ALLPROTO").setStyle(ButtonStyle.Success),
  );
}

function buildAddModal(protocol) {
  const modal = new ModalBuilder()
    .setCustomId(`addmodal:${protocol}`)
    .setTitle(`Create Account (${protocol})`);

  const usernameInput = new TextInputBuilder()
    .setCustomId("username")
    .setLabel("Username (tanpa suffix) [A-Za-z0-9_]")
    .setStyle(TextInputStyle.Short)
    .setRequired(true)
    .setMinLength(1)
    .setMaxLength(32);

  const daysInput = new TextInputBuilder()
    .setCustomId("days")
    .setLabel("Masa aktif (hari) 1..3650")
    .setStyle(TextInputStyle.Short)
    .setRequired(true)
    .setPlaceholder("30");

  const quotaInput = new TextInputBuilder()
    .setCustomId("quota_gb")
    .setLabel("Quota (GB) 0=unlimited")
    .setStyle(TextInputStyle.Short)
    .setRequired(true)
    .setPlaceholder("0");

  modal.addComponents(
    new ActionRowBuilder().addComponents(usernameInput),
    new ActionRowBuilder().addComponents(daysInput),
    new ActionRowBuilder().addComponents(quotaInput),
  );

  return modal;
}

async function registerCommands() {
  const commands = [
    new SlashCommandBuilder().setName("help").setDescription("Cara pakai bot & penjelasan fungsi"),
    new SlashCommandBuilder().setName("ping").setDescription("Health check bot + backend latency (ms)"),
    new SlashCommandBuilder().setName("status").setDescription("Status service Xray dan Nginx (admin only)"),

    new SlashCommandBuilder().setName("notify").setDescription("Panel notifikasi berkala Ping+Status (admin only)"),

    new SlashCommandBuilder()
      .setName("accounts")
      .setDescription("List akun + ambil ulang XRAY ACCOUNT DETAIL (.txt) (admin only)"),

    new SlashCommandBuilder()
      .setName("add")
      .setDescription("Create Xray user (interactive: pilih protocol via button) (admin only)"),

    new SlashCommandBuilder()
      .setName("del")
      .setDescription("Delete Xray user (list & confirm) (admin only)")
      .addStringOption(o =>
        o.setName("protocol")
          .setDescription("Untuk delete langsung: isi protocol + username. Untuk list: optional sebagai initial filter.")
          .setRequired(false)
          .addChoices(
            { name: "all", value: "all" },
            { name: "vless", value: "vless" },
            { name: "vmess", value: "vmess" },
            { name: "trojan", value: "trojan" },
            { name: "allproto", value: "allproto" },
          )
      )
      .addStringOption(o =>
        o.setName("username")
          .setDescription("Jika diisi, bot akan minta confirm delete untuk user ini (tanpa suffix)")
          .setRequired(false)
      ),
  ].map(c => c.toJSON());

  const rest = new REST({ version: "10" }).setToken(TOKEN);
  await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once("ready", () => {
  console.log(`Logged in as ${client.user.tag}`);

  loadNotifyCfg();
  startNotifyScheduler(client);
});

client.on("interactionCreate", async (interaction) => {

  // --------------------
  // MODALS
  // --------------------
  if (interaction.isModalSubmit()) {
    try {
      if (String(interaction.guildId) !== String(GUILD_ID)) {
        return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
      }

      const cid = String(interaction.customId || "");

      // notify interval modal
      if (cid === "notify:interval_modal") {
        if (!isAdmin(interaction.member)) {
          return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
        }

        const raw = String(interaction.fields.getTextInputValue("minutes") || "").trim();
        const minutes = parseInt(raw, 10);
        if (!Number.isInteger(minutes) || minutes < NOTIFY_MIN_INTERVAL_MIN || minutes > NOTIFY_MAX_INTERVAL_MIN) {
          return interaction.reply({
            content: `❌ Interval tidak valid. Masukkan angka ${NOTIFY_MIN_INTERVAL_MIN}..${NOTIFY_MAX_INTERVAL_MIN}.`,
            ephemeral: true
          });
        }

        notifyCfg.interval_min = minutes;
        notifyCfg.last_error = null;
        saveNotifyCfg();
        startNotifyScheduler(client);

        const panel = buildNotifyPanel();
        return interaction.reply({ ...panel, ephemeral: true });
      }

      // add modal
      if (!cid.startsWith("addmodal:")) {
        return interaction.reply({ content: "❌ Unknown modal", ephemeral: true });
      }

      if (!isAdmin(interaction.member)) {
        return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
      }

      const protocol = cid.split(":")[1] || "";
      if (!ADD_PROTOCOLS.includes(protocol)) {
        return interaction.reply({ content: "❌ Invalid protocol", ephemeral: true });
      }

      const usernameRaw = String(interaction.fields.getTextInputValue("username") || "").trim();
      const daysRaw = String(interaction.fields.getTextInputValue("days") || "").trim();
      const quotaRaw = String(interaction.fields.getTextInputValue("quota_gb") || "").trim();

      const days = parseInt(daysRaw, 10);
      const quota_gb = Number(quotaRaw);

      const v = lightValidate(protocol, usernameRaw, days, quota_gb);
      if (!v.ok) {
        return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });
      }

      await interaction.deferReply({ ephemeral: true });

      const resp = await callBackend({ action: "add", protocol: v.protocol, username: usernameRaw, days, quota_gb });
      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Failed: ${resp.error || "unknown error"}`);
      }

      const finalEmail = resp.username;
      const secret = resp.password || resp.uuid || "(hidden)";
      const detailPath = resp.detail_path;

      const embed = new EmbedBuilder()
        .setTitle("✅ Created")
        .setDescription("Akun berhasil dibuat. Detail terlampir sebagai file .txt.")
        .addFields(
          { name: "Protocol", value: v.protocol, inline: true },
          { name: "Username", value: finalEmail, inline: true },
          { name: "UUID/Pass", value: `\`${secret}\``, inline: false },
          { name: "Valid Until", value: resp.expired_at || "-", inline: true },
          { name: "Quota", value: `${quota_gb} GB`, inline: true },
        )
        .setFooter({ text: "Klik tombol untuk ambil ulang file .txt" });

      const files = [];
      if (detailPath && fs.existsSync(detailPath)) {
        files.push(new AttachmentBuilder(detailPath, { name: path.basename(detailPath) }));
      }

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId(`detail:${v.protocol}:${finalEmail}`)
          .setLabel("Resend Detail TXT")
          .setStyle(ButtonStyle.Secondary)
      );

      return interaction.editReply({ content: null, embeds: [embed], components: [row], files });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // --------------------
  // SELECT MENUS
  // --------------------
  if (interaction.isChannelSelectMenu && interaction.isChannelSelectMenu()) {
    try {
      if (String(interaction.guildId) !== String(GUILD_ID)) {
        return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
      }
      if (!isAdmin(interaction.member)) {
        return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
      }

      const cid = String(interaction.customId || "");
      if (cid !== "notify:channel_select") {
        return interaction.reply({ content: "❌ Unknown menu", ephemeral: true });
      }

      const selected = interaction.values && interaction.values[0] ? String(interaction.values[0]) : null;
      if (!selected) {
        return interaction.reply({ content: "❌ Tidak ada channel dipilih.", ephemeral: true });
      }

      notifyCfg.channel_id = selected;
      notifyCfg.last_error = null;
      saveNotifyCfg();
      startNotifyScheduler(client);

      const panel = buildNotifyPanel();
      return interaction.update({ ...panel });
    } catch (e) {
      console.error(e);
      return interaction.reply({ content: `❌ ${mapBackendError(e)}`, ephemeral: true });
    }
  }

  if (interaction.isStringSelectMenu()) {
    try {
      if (String(interaction.guildId) !== String(GUILD_ID)) {
        return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
      }
      if (!isAdmin(interaction.member)) {
        return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
      }

      const customId = String(interaction.customId || "");

      // accounts select: acct:sel:<protoFilter>:<offset>
      if (customId.startsWith("acct:sel:")) {
        const selected = (interaction.values && interaction.values[0]) ? String(interaction.values[0]) : "";
        const parsed = parseFinalEmail(selected);
        if (!parsed) return interaction.reply({ content: "❌ Invalid target", ephemeral: true });

        const txtPath = buildDetailTxtPath(parsed.proto, parsed.final);
        if (!txtPath) return interaction.reply({ content: "❌ Invalid target", ephemeral: true });

        await interaction.deferReply({ ephemeral: true });

        if (!fs.existsSync(txtPath)) {
          return interaction.editReply(`❌ File not found: ${txtPath}`);
        }

        const file = new AttachmentBuilder(txtPath, { name: path.basename(txtPath) });
        const embed = new EmbedBuilder()
          .setTitle("📄 XRAY ACCOUNT DETAIL")
          .addFields(
            { name: "Protocol", value: parsed.proto, inline: true },
            { name: "Username", value: parsed.final, inline: true }
          )
          .setFooter({ text: "Attached: XRAY ACCOUNT DETAIL (.txt)" });

        return interaction.editReply({ content: null, embeds: [embed], files: [file] });
      }

      // delete select: del:sel:<protoFilter>:<offset>
      if (customId.startsWith("del:sel:")) {
        const selected = (interaction.values && interaction.values[0]) ? String(interaction.values[0]) : "";
        const parsed = parseFinalEmail(selected);
        if (!parsed) return interaction.reply({ content: "❌ Invalid target", ephemeral: true });

        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder()
            .setCustomId(`delconfirm:${parsed.proto}:${parsed.base}`)
            .setLabel("Confirm Delete")
            .setStyle(ButtonStyle.Danger),
          new ButtonBuilder()
            .setCustomId(`delcancel:${parsed.proto}:${parsed.base}`)
            .setLabel("Cancel")
            .setStyle(ButtonStyle.Secondary),
        );

        const embed = new EmbedBuilder()
          .setTitle("⚠️ Confirm Delete")
          .setDescription("Klik **Confirm Delete** untuk menghapus akun ini.")
          .addFields(
            { name: "Protocol", value: parsed.proto, inline: true },
            { name: "Username", value: parsed.final, inline: true },
          )
          .setFooter({ text: "Ini akan menghapus user dari config + metadata files." });

        return interaction.update({
          content: null,
          embeds: [embed],
          components: [row]
        });
      }

      return interaction.reply({ content: "❌ Unknown menu", ephemeral: true });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // --------------------
  // BUTTONS
  // --------------------
  if (interaction.isButton()) {
    try {
      if (String(interaction.guildId) !== String(GUILD_ID)) {
        return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
      }

      const customId = String(interaction.customId || "");

      // /notify buttons (admin only)
      if (customId.startsWith("notify:")) {
        if (!isAdmin(interaction.member)) {
          return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
        }

        // refresh panel
        if (customId === "notify:refresh") {
          await interaction.deferUpdate();
          const panel = buildNotifyPanel();
          return interaction.editReply({ ...panel });
        }

        // set channel -> show channel select menu
        if (customId === "notify:set_channel") {
          const extraRow = buildNotifyChannelSelectRow();
          const panel = buildNotifyPanel({ extraRow });
          return interaction.update({ ...panel });
        }

        // set interval -> modal
        if (customId === "notify:set_interval") {
          const modal = buildNotifyIntervalModal();
          return interaction.showModal(modal);
        }

        // toggle enable/disable
        if (customId === "notify:toggle") {
          await interaction.deferUpdate();

          if (!notifyCfg.enabled) {
            // enabling requires channel set
            if (!notifyCfg.channel_id) {
              notifyCfg.last_error = "Channel belum diatur. Klik Set Channel terlebih dahulu.";
              saveNotifyCfg();
              const panel = buildNotifyPanel();
              await interaction.editReply({ ...panel });
              return interaction.followUp({ content: "❌ Channel belum diatur. Klik **Set Channel** dulu.", ephemeral: true });
            }

            notifyCfg.enabled = true;
            notifyCfg.last_error = null;
            saveNotifyCfg();
            startNotifyScheduler(client);

            const panel = buildNotifyPanel();
            await interaction.editReply({ ...panel });
            return interaction.followUp({ content: "✅ Notify diaktifkan. Gunakan **Test Now** untuk kirim 1x sekarang.", ephemeral: true });
          }

          // disabling
          notifyCfg.enabled = false;
          saveNotifyCfg();
          stopNotifyScheduler();

          const panel = buildNotifyPanel();
          await interaction.editReply({ ...panel });
          return interaction.followUp({ content: "✅ Notify dimatikan.", ephemeral: true });
        }

        // test now
        if (customId === "notify:test") {
          await interaction.deferUpdate();

          if (!notifyCfg.channel_id) {
            notifyCfg.last_error = "Channel belum diatur. Klik Set Channel terlebih dahulu.";
            saveNotifyCfg();
            const panel = buildNotifyPanel();
            await interaction.editReply({ ...panel });
            return interaction.followUp({ content: "❌ Channel belum diatur. Klik **Set Channel** dulu.", ephemeral: true });
          }

          // send 1x now (even if disabled)
          await sendNotifyTick(client).catch((e) => {
            notifyCfg.last_error = mapBackendError(e);
            saveNotifyCfg();
          });

          const panel = buildNotifyPanel();
          await interaction.editReply({ ...panel });
          return interaction.followUp({ content: "✅ Test dikirim (cek channel target).", ephemeral: true });
        }

        return interaction.reply({ content: "❌ Unknown notify action", ephemeral: true });
      }

      // /help tabs are unchanged (if you use them elsewhere); keep minimal stable behavior
      // ✅ /add protocol selector buttons
      if (customId.startsWith("addproto:")) {
        if (!isAdmin(interaction.member)) {
          return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
        }
        const protocol = customId.split(":")[1] || "";
        if (!ADD_PROTOCOLS.includes(protocol)) {
          return interaction.reply({ content: "❌ Invalid protocol", ephemeral: true });
        }
        const modal = buildAddModal(protocol);
        return interaction.showModal(modal);
      }

      // Protocol filter buttons for /accounts & /del list
      if (customId.startsWith("filt:")) {
        if (!isAdmin(interaction.member)) {
          return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
        }
        const parts = customId.split(":");
        if (parts.length !== 3) return interaction.reply({ content: "❌ Invalid filter button", ephemeral: true });

        const prefix = String(parts[1] || "").trim(); // acct|del
        const proto = String(parts[2] || "all").toLowerCase().trim();

        if (!["acct", "del"].includes(prefix)) {
          return interaction.reply({ content: "❌ Invalid filter target", ephemeral: true });
        }
        if (!LIST_PROTOCOLS.includes(proto)) {
          return interaction.reply({ content: "❌ Invalid filter protocol", ephemeral: true });
        }

        await interaction.deferUpdate();
        const payload = await buildListMessage(prefix === "del" ? "del" : "acct", proto, 0);

        return interaction.editReply({
          content: null,
          embeds: payload.embeds,
          components: payload.components,
          files: []
        });
      }

      // paging buttons for accounts/delete lists (Prev/Next only)
      if (customId.startsWith("acct:") || customId.startsWith("del:")) {
        if (!isAdmin(interaction.member)) {
          return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
        }
        const parts = customId.split(":");
        if (parts.length !== 4) return interaction.reply({ content: "❌ Invalid button", ephemeral: true });

        const prefix = parts[0]; // acct|del
        const kind = String(parts[1] || "").trim(); // prev|next
        const protoFilter = String(parts[2] || "all").toLowerCase().trim();
        const offset = clampInt(parseInt(parts[3], 10), 0, 10_000_000);

        if (!LIST_PROTOCOLS.includes(protoFilter)) {
          return interaction.reply({ content: "❌ Invalid filter state", ephemeral: true });
        }

        let nextOffset = offset;
        if (kind === "next") nextOffset = offset + PAGE_SIZE;
        else if (kind === "prev") nextOffset = Math.max(0, offset - PAGE_SIZE);
        else return interaction.reply({ content: "❌ Invalid navigation button", ephemeral: true });

        await interaction.deferUpdate();
        const payload = await buildListMessage(prefix === "del" ? "del" : "acct", protoFilter, nextOffset);

        return interaction.editReply({
          content: null,
          embeds: payload.embeds,
          components: payload.components,
          files: []
        });
      }

      // detail:<proto>:<finalEmail>
      if (customId.startsWith("detail:")) {
        if (!isAdmin(interaction.member)) {
          return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
        }
        const parts = customId.split(":");
        if (parts.length !== 3) return interaction.reply({ content: "❌ Invalid button", ephemeral: true });

        const proto = String(parts[1] || "").toLowerCase().trim();
        const finalEmail = String(parts[2] || "").trim();
        if (!ADD_PROTOCOLS.includes(proto)) {
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

        return interaction.editReply({ content: null, embeds: [embed], files: [file] });
      }

      // delconfirm:<proto>:<username>  / delcancel:<proto>:<username>
      if (customId.startsWith("delconfirm:") || customId.startsWith("delcancel:")) {
        if (!isAdmin(interaction.member)) {
          return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
        }
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
          const embed = new EmbedBuilder().setTitle("❌ Failed").setDescription(resp.error || "unknown error");
          return interaction.editReply({ content: null, embeds: [embed], components: [] });
        }

        const embed = new EmbedBuilder()
          .setTitle("🗑️ Deleted")
          .setDescription("Akun berhasil dihapus.")
          .addFields(
            { name: "Protocol", value: proto, inline: true },
            { name: "Username", value: resp.username || `${username}@${proto}`, inline: true },
          )
          .setFooter({ text: "User removed from config and metadata cleaned." });

        return interaction.editReply({ content: null, embeds: [embed], components: [] });
      }

      return interaction.reply({ content: "❌ Unknown button", ephemeral: true });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
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

  if (cmd === "help") {
    const embed = new EmbedBuilder()
      .setTitle("📘 XRAY Discord Bot Help")
      .setDescription("Bot ini untuk manajemen akun Xray via backend service (IPC).")
      .addFields(
        { name: "/add", value: "Buat akun: pilih protocol via button, lalu isi form (username/days/quota). **Admin only**", inline: false },
        { name: "/del", value: "Hapus akun via list+pilih+confirm. Atau isi protocol+username untuk confirm langsung. **Admin only**", inline: false },
        { name: "/accounts", value: "List akun (paging) + pilih untuk ambil ulang detail (.txt). **Admin only**", inline: false },
        { name: "/notify", value: "Panel notifikasi berkala Ping+Status (set channel, interval, enable/disable). **Admin only**", inline: false },
        { name: "/ping", value: "Cek bot hidup + latency backend (ms).", inline: false },
        { name: "/status", value: "Lihat status service Xray & Nginx. **Admin only**", inline: false },
        { name: "Aturan username", value: "`[A-Za-z0-9_]` (tanpa suffix). Bot akan menambahkan `@vless/@vmess/@trojan/@allproto`.", inline: false },
        { name: "Quota", value: "`quota_gb=0` berarti Unlimited.", inline: false }
      )
      .setFooter({ text: "Tip: Jika error socket/backend, cek /status (admin) atau journalctl xray-backend." });

    return interaction.reply({ embeds: [embed], ephemeral: true });
  }

  // /ping (content-only)
  if (cmd === "ping") {
    try {
      const wsMs = Math.round(client.ws.ping);
      const t0 = Date.now();
      const work = callBackend({ action: "ping" });

      const quick = await Promise.race([
        work.then((r) => ({ ok: true, r })),
        new Promise((res) => setTimeout(() => res(null), QUICK_REPLY_MS)),
      ]);

      if (quick) {
        if (!quick.ok || quick.r.status !== "ok") {
          const msg = quick.r && quick.r.error ? quick.r.error : "unknown error";
          return interaction.reply({ content: `❌ Backend ping failed: ${msg}`, ephemeral: true });
        }
        const ipcMs = Date.now() - t0;
        return interaction.reply({ content: buildPingText(wsMs, ipcMs), ephemeral: true });
      }

      await interaction.deferReply({ ephemeral: true });
      const resp = await work;
      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Backend ping failed: ${resp.error || "unknown error"}`);
      }
      const ipcMs = Date.now() - t0;
      return interaction.editReply({ content: buildPingText(wsMs, ipcMs) });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // Admin-only commands below
  if (!isAdmin(interaction.member)) {
    return interaction.reply({ content: "❌ Unauthorized (admin role required).", ephemeral: true });
  }

  // /status (content-only)
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
          const msg = quick.r && quick.r.error ? quick.r.error : "unknown error";
          return interaction.reply({ content: `❌ Failed: ${msg}`, ephemeral: true });
        }
        const ipcMs = Date.now() - t0;
        return interaction.reply({ content: buildStatusText(quick.r.xray, quick.r.nginx, ipcMs), ephemeral: true });
      }

      await interaction.deferReply({ ephemeral: true });
      const resp = await work;
      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Failed: ${resp.error || "unknown error"}`);
      }
      const ipcMs = Date.now() - t0;
      return interaction.editReply({ content: buildStatusText(resp.xray, resp.nginx, ipcMs) });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // /notify -> open panel
  if (cmd === "notify") {
    const panel = buildNotifyPanel();
    return interaction.reply({ ...panel, ephemeral: true });
  }

  // /accounts
  if (cmd === "accounts") {
    try {
      await interaction.deferReply({ ephemeral: true });
      const payload = await buildListMessage("acct", "all", 0);
      return interaction.editReply({
        content: null,
        embeds: payload.embeds,
        components: payload.components
      });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // /add
  if (cmd === "add") {
    const row = buildAddProtocolButtons();
    const msg =
      "🧩 **Create Account**\n" +
      "1) Pilih protocol via button\n" +
      "2) Isi form (username/days/quota)\n\n" +
      "Catatan: username tanpa suffix, hanya `[A-Za-z0-9_]`";
    return interaction.reply({ content: msg, components: [row], ephemeral: true });
  }

  // /del — two modes
  if (cmd === "del") {
    const protocolOpt = interaction.options.getString("protocol");
    const usernameOpt = interaction.options.getString("username");

    if (protocolOpt && usernameOpt) {
      const protocol = String(protocolOpt).toLowerCase().trim();
      const username = String(usernameOpt).trim();

      const v = lightValidate(protocol, username);
      if (!v.ok) return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId(`delconfirm:${v.protocol}:${username}`)
          .setLabel("Confirm Delete")
          .setStyle(ButtonStyle.Danger),
        new ButtonBuilder()
          .setCustomId(`delcancel:${v.protocol}:${username}`)
          .setLabel("Cancel")
          .setStyle(ButtonStyle.Secondary),
      );

      const embed = new EmbedBuilder()
        .setTitle("⚠️ Confirm Delete")
        .setDescription("Klik **Confirm Delete** untuk menghapus akun ini.")
        .addFields(
          { name: "Protocol", value: v.protocol, inline: true },
          { name: "Username", value: `${username}@${v.protocol}`, inline: true },
        )
        .setFooter({ text: "Ini akan menghapus user dari config + metadata files." });

      return interaction.reply({ embeds: [embed], components: [row], ephemeral: true });
    }

    if (!protocolOpt && usernameOpt) {
      return interaction.reply({
        content: "❌ Jika ingin delete langsung, isi juga option protocol. Atau jalankan /del tanpa username untuk mode list.",
        ephemeral: true
      });
    }

    try {
      const initialFilter = protocolOpt ? String(protocolOpt).toLowerCase().trim() : "all";
      const protoFilter = LIST_PROTOCOLS.includes(initialFilter) ? initialFilter : "all";

      await interaction.deferReply({ ephemeral: true });
      const payload = await buildListMessage("del", protoFilter, 0);

      return interaction.editReply({
        content: null,
        embeds: payload.embeds,
        components: payload.components
      });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  return interaction.reply({ content: "❌ Unknown command", ephemeral: true });
});

(async () => {
  try {
    await registerCommands();
    await client.login(TOKEN);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();