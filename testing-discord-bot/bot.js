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
  TextInputStyle
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

// ✅ /ping & /status tetap content-only (tidak diminta berubah)
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
 * ✅ UPDATED TABLE: only No & Username
 * Used by /accounts list and /del list
 */
function formatAccountsTable(items) {
  const header = "No  Username";
  const lines = [header];
  for (let i = 0; i < items.length; i++) {
    const it = items[i] || {};
    const no = String(i + 1).padEnd(3, " ");
    // keep username width reasonable for embed; truncate for safety
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
 * /help row filter buttons (tabs)
 * max 5 per row, so we use 5 tabs: accounts/add/del/ping/status
 * "overview" is default shown when /help invoked.
 */
function buildHelpTabRow(activeTab) {
  activeTab = String(activeTab || "overview").toLowerCase().trim();
  if (!HELP_TABS.includes(activeTab)) activeTab = "overview";

  const mk = (tab, label, emoji) => {
    const isActive = activeTab === tab;
    return new ButtonBuilder()
      .setCustomId(`help:tab:${tab}`)
      .setLabel(label)
      .setEmoji(emoji)
      .setStyle(isActive ? ButtonStyle.Primary : ButtonStyle.Secondary);
  };

  // exactly 5 buttons
  return new ActionRowBuilder().addComponents(
    mk("accounts", "Accounts", "📚"),
    mk("add", "Add", "➕"),
    mk("del", "Del", "🗑️"),
    mk("ping", "Ping", "🏓"),
    mk("status", "Status", "🧩"),
  );
}

function buildHelpEmbed(tab) {
  tab = String(tab || "overview").toLowerCase().trim();
  if (!HELP_TABS.includes(tab)) tab = "overview";

  const e = new EmbedBuilder().setTitle("📘 XRAY Discord Bot Help");

  if (tab === "overview") {
    e.setDescription(
      [
        "Bot ini untuk manajemen akun Xray via backend service (IPC).",
        "",
        "Pilih tab di bawah untuk melihat detail per command.",
        "",
        "**Catatan role:** beberapa command hanya bisa dipakai admin (ADMIN_ROLE_ID).",
      ].join("\n")
    );
    e.addFields(
      { name: "/accounts", value: "List akun + pilih untuk ambil ulang detail .txt (admin only)", inline: false },
      { name: "/add", value: "Buat akun (protocol via button → modal) (admin only)", inline: false },
      { name: "/del", value: "Hapus akun (list+confirm atau direct confirm) (admin only)", inline: false },
      { name: "/ping", value: "Health check bot + backend latency", inline: false },
      { name: "/status", value: "Status service Xray & Nginx (admin only)", inline: false },
    );
    e.setFooter({ text: "Tip: Jika backend/socket error → cek xray-backend.service dan file socket /run/xray-backend.sock" });
    return e;
  }

  if (tab === "accounts") {
    e.setDescription(
      [
        "**/accounts** (admin only)",
        "",
        "Menampilkan daftar akun (tabel: No & Username) + dropdown untuk pilih akun.",
        "Filter protocol dilakukan via tombol filter (ALL/VLESS/VMESS/TROJAN/ALLPROTO).",
        "",
        "Langkah:",
        "1) Jalankan `/accounts`",
        "2) (Opsional) klik tombol filter protocol",
        "3) Pilih akun dari dropdown → bot attach ulang file **XRAY ACCOUNT DETAIL (.txt)**",
      ].join("\n")
    );
    return e;
  }

  if (tab === "add") {
    e.setDescription(
      [
        "**/add** (admin only)",
        "",
        "Flow interaktif:",
        "1) Jalankan `/add`",
        "2) Pilih protocol via button",
        "3) Isi modal: username (tanpa suffix), days, quota_gb",
        "",
        "Aturan:",
        "- username valid: `[A-Za-z0-9_]`",
        "- quota_gb: `0` = unlimited",
        "",
        "Hasil sukses:",
        "- Bot meng-attach file **XRAY ACCOUNT DETAIL (.txt)**",
      ].join("\n")
    );
    return e;
  }

  if (tab === "del") {
    e.setDescription(
      [
        "**/del** (admin only)",
        "",
        "Mode list (recommended):",
        "1) Jalankan `/del`",
        "2) (Opsional) klik tombol filter protocol",
        "3) Pilih akun dari dropdown",
        "4) Konfirmasi delete (Confirm / Cancel)",
        "",
        "Mode direct confirm:",
        "- `/del protocol:<vless|vmess|trojan|allproto> username:<name>`",
      ].join("\n")
    );
    return e;
  }

  if (tab === "ping") {
    e.setDescription(
      [
        "**/ping**",
        "",
        "Menampilkan health check bot dan latency IPC ke backend (ms).",
      ].join("\n")
    );
    return e;
  }

  if (tab === "status") {
    e.setDescription(
      [
        "**/status** (admin only)",
        "",
        "Menampilkan status service:",
        "- Xray",
        "- Nginx",
        "",
        "Serta latency IPC ke backend (ms).",
      ].join("\n")
    );
    return e;
  }

  e.setDescription("Help tab not found.");
  return e;
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
            // dropdown masih menampilkan info tambahan biar mudah pilih (ini bukan "table")
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
});

client.on("interactionCreate", async (interaction) => {

  // --------------------
  // MODALS (for /add)
  // --------------------
  if (interaction.isModalSubmit()) {
    try {
      if (String(interaction.guildId) !== String(GUILD_ID)) {
        return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
      }
      if (!isAdmin(interaction.member)) {
        return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
      }

      const cid = String(interaction.customId || "");
      if (!cid.startsWith("addmodal:")) {
        return interaction.reply({ content: "❌ Unknown modal", ephemeral: true });
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
      const jsonPath = resp.detail_json_path;

      const embed = new EmbedBuilder()
        .setTitle("✅ Created")
        .setDescription("Akun berhasil dibuat. Detail terlampir sebagai file .txt.")
        .addFields(
          { name: "Protocol", value: v.protocol, inline: true },
          { name: "Username", value: finalEmail, inline: true },
          { name: "UUID/Pass", value: `\`${secret}\``, inline: false },
          { name: "Valid Until", value: resp.expired_at || "-", inline: true },
          { name: "Quota", value: `${quota_gb} GB`, inline: true },
          { name: "Metadata JSON", value: jsonPath ? `\`${jsonPath}\`` : "-", inline: false },
        )
        .setFooter({ text: "Button: Resend Detail TXT untuk ambil ulang file .txt" });

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
  // SELECT MENUS (admin only)
  // --------------------
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

      // /help tabs — allowed for everyone
      if (customId.startsWith("help:tab:")) {
        const tab = customId.split(":")[2] || "overview";
        const embed = buildHelpEmbed(tab);
        const row = buildHelpTabRow(tab);
        return interaction.update({ content: null, embeds: [embed], components: [row] });
      }

      // Everything else requires admin
      if (!isAdmin(interaction.member)) {
        return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
      }

      // Protocol filter buttons for /accounts & /del list
      if (customId.startsWith("filt:")) {
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

      // /add protocol selector buttons
      if (customId.startsWith("addproto:")) {
        const protocol = customId.split(":")[1] || "";
        if (!ADD_PROTOCOLS.includes(protocol)) {
          return interaction.reply({ content: "❌ Invalid protocol", ephemeral: true });
        }
        const modal = buildAddModal(protocol);
        return interaction.showModal(modal);
      }

      // paging buttons for accounts/delete lists (Prev/Next only)
      if (customId.startsWith("acct:") || customId.startsWith("del:")) {
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

  if (!interaction.isChatInputCommand()) return;

  if (String(interaction.guildId) !== String(GUILD_ID)) {
    return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
  }

  const cmd = interaction.commandName;

  // /help
  if (cmd === "help") {
    const embed = buildHelpEmbed("overview");
    const row = buildHelpTabRow("overview");
    return interaction.reply({ embeds: [embed], components: [row], ephemeral: true });
  }

  // /ping content-only
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

  // /status content-only
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

  // /accounts embed-only list
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

  // /add starts protocol selection with buttons
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