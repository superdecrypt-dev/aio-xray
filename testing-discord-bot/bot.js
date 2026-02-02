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

const PAGE_SIZE = 25; // Discord select menu max options

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

function buildPingPayload(wsMs, ipcMs) {
  const embed = new EmbedBuilder()
    .setTitle("🏓 Pong")
    .addFields(
      { name: "Bot", value: "🟢 OK", inline: true },
      { name: "Discord WS", value: `${wsMs} ms`, inline: true },
      { name: "Backend IPC", value: `${ipcMs} ms`, inline: true },
    )
    .setFooter({ text: "Latency = round-trip IPC ke backend." });

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

function formatAccountsTable(items) {
  const header = "No  Username                 Type     Expired";
  const lines = [header];
  for (let i = 0; i < items.length; i++) {
    const it = items[i] || {};
    const no = String(i + 1).padEnd(3, " ");
    const user = String(it.username || "-").slice(0, 22).padEnd(22, " ");
    const proto = String(it.protocol || "-").slice(0, 8).padEnd(8, " ");
    const exp = String(it.expired_at || "-").slice(0, 10);
    lines.push(`${no}${user}  ${proto} ${exp}`);
  }
  return "```\n" + lines.join("\n") + "\n```";
}

async function buildListMessage(kind, protoFilter, offset) {
  // kind: "acct" or "del"
  protoFilter = String(protoFilter || "all").toLowerCase().trim();
  offset = clampInt(Number(offset || 0), 0, 10_000_000);

  const resp = await callBackend({
    action: "list",
    protocol: protoFilter,
    offset,
    limit: PAGE_SIZE
  });

  if (!resp || resp.status !== "ok") {
    return {
      content: `❌ Failed: ${resp && resp.error ? resp.error : "unknown error"}`,
      embeds: [],
      components: [],
      ephemeral: true
    };
  }

  const items = Array.isArray(resp.items) ? resp.items : [];
  const total = Number.isFinite(resp.total) ? resp.total : items.length;
  const hasMore = !!resp.has_more;

  const title = kind === "del" ? "🗑️ Delete Accounts" : "📚 XRAY Accounts";
  const desc = items.length ? formatAccountsTable(items) : "Tidak ada akun ditemukan.";

  const embed = new EmbedBuilder()
    .setTitle(title)
    .setDescription(desc)
    .setFooter({ text: `Filter: ${protoFilter} | Showing ${items.length} of ${total} | Offset ${offset}` });

  const prefix = kind === "del" ? "del" : "acct";

  const nav = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId(`${prefix}:prev:${protoFilter}:${offset}`)
      .setLabel("Prev")
      .setStyle(ButtonStyle.Secondary)
      .setEmoji("⬅️")
      .setDisabled(offset <= 0),
    new ButtonBuilder()
      .setCustomId(`${prefix}:ref:${protoFilter}:${offset}`)
      .setLabel("Refresh")
      .setStyle(ButtonStyle.Secondary)
      .setEmoji("🔄"),
    new ButtonBuilder()
      .setCustomId(`${prefix}:next:${protoFilter}:${offset}`)
      .setLabel("Next")
      .setStyle(ButtonStyle.Secondary)
      .setEmoji("➡️")
      .setDisabled(!hasMore),
  );

  const components = [nav];

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

    components.unshift(new ActionRowBuilder().addComponents(menu));
  }

  const content = kind === "del"
    ? (items.length ? "🗑️ Delete mode — pilih akun dari dropdown, lalu konfirmasi." : "🗑️ Delete mode — tidak ada akun.")
    : (items.length ? "📚 XRAY Accounts — pilih dari dropdown untuk ambil ulang file .txt" : "📚 XRAY Accounts — tidak ada akun.");

  return { content, embeds: [embed], components, ephemeral: true };
}

async function registerCommands() {
  const commands = [
    new SlashCommandBuilder().setName("help").setDescription("Cara pakai bot & penjelasan fungsi"),
    new SlashCommandBuilder().setName("ping").setDescription("Health check bot + backend latency (ms)"),
    new SlashCommandBuilder().setName("status").setDescription("Status service Xray dan Nginx (admin only)"),

    new SlashCommandBuilder()
      .setName("accounts")
      .setDescription("List akun + ambil ulang XRAY ACCOUNT DETAIL (.txt) (admin only)")
      .addStringOption(o =>
        o.setName("protocol")
          .setDescription("Filter protocol")
          .setRequired(false)
          .addChoices(
            { name: "all", value: "all" },
            { name: "vless", value: "vless" },
            { name: "vmess", value: "vmess" },
            { name: "trojan", value: "trojan" },
            { name: "allproto", value: "allproto" },
          )
      )
      .addIntegerOption(o =>
        o.setName("page")
          .setDescription("Halaman (1=awal)")
          .setRequired(false)
          .setMinValue(1)
      ),

    new SlashCommandBuilder()
      .setName("add")
      .setDescription("Create Xray user (via Python backend)")
      .addStringOption(o => o.setName("protocol").setDescription("vless/vmess/trojan/allproto").setRequired(true))
      .addStringOption(o => o.setName("username").setDescription("username tanpa suffix [a-zA-Z0-9_]").setRequired(true))
      .addIntegerOption(o => o.setName("days").setDescription("masa aktif (hari)").setRequired(true))
      .addNumberOption(o => o.setName("quota_gb").setDescription("quota (GB), 0=unlimited").setRequired(true)),

    // /del: bisa dua mode
    // - Mode A (interactive): tanpa username => tampil list + pilih + confirm
    // - Mode B (direct): protocol+username => confirm seperti sebelumnya
    new SlashCommandBuilder()
      .setName("del")
      .setDescription("Delete Xray user (list & confirm) (admin only)")
      .addStringOption(o =>
        o.setName("protocol")
          .setDescription("Filter protocol untuk list, atau protocol untuk delete langsung")
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
      )
      .addIntegerOption(o =>
        o.setName("page")
          .setDescription("Halaman list (1=awal)")
          .setRequired(false)
          .setMinValue(1)
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
  // SELECT MENUS
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

        return interaction.editReply({ content: "✅ Detail attached.", embeds: [embed], files: [file] });
      }

      // delete select: del:sel:<protoFilter>:<offset>
      if (customId.startsWith("del:sel:")) {
        const selected = (interaction.values && interaction.values[0]) ? String(interaction.values[0]) : "";
        const parsed = parseFinalEmail(selected);
        if (!parsed) return interaction.reply({ content: "❌ Invalid target", ephemeral: true });

        // Reuse existing confirm button format: delconfirm:<proto>:<baseUser>
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

        // Use update (replace list UI with confirm UI)
        return interaction.update({
          content: `⚠️ Confirm delete: ${parsed.final}`,
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
      if (!isAdmin(interaction.member)) {
        return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
      }

      const customId = String(interaction.customId || "");

      // paging buttons for accounts/delete lists
      // acct:<prev|ref|next>:<protoFilter>:<offset>
      // del:<prev|ref|next>:<protoFilter>:<offset>
      if (customId.startsWith("acct:") || customId.startsWith("del:")) {
        const parts = customId.split(":");
        if (parts.length !== 4) return interaction.reply({ content: "❌ Invalid button", ephemeral: true });

        const prefix = parts[0]; // acct|del
        const kind = String(parts[1] || "").trim();
        const protoFilter = String(parts[2] || "all").toLowerCase().trim();
        const offset = clampInt(parseInt(parts[3], 10), 0, 10_000_000);

        let nextOffset = offset;
        if (kind === "next") nextOffset = offset + PAGE_SIZE;
        else if (kind === "prev") nextOffset = Math.max(0, offset - PAGE_SIZE);
        else if (kind === "ref") nextOffset = offset;
        else return interaction.reply({ content: "❌ Invalid button", ephemeral: true });

        await interaction.deferUpdate();
        const payload = await buildListMessage(prefix === "del" ? "del" : "acct", protoFilter, nextOffset);

        return interaction.editReply({
          content: payload.content,
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
          .setTitle("🗑️ Deleted")
          .addFields(
            { name: "Protocol", value: proto, inline: true },
            { name: "Username", value: resp.username || `${username}@${proto}`, inline: true },
          )
          .setFooter({ text: "User removed from config and metadata cleaned." });

        return interaction.editReply({ content: "✅ Deleted.", embeds: [embed], components: [] });
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

  if (cmd === "help") {
    const embed = new EmbedBuilder()
      .setTitle("📘 XRAY Discord Bot Help")
      .setDescription("Bot ini untuk manajemen akun Xray via backend service (IPC).")
      .addFields(
        { name: "/add", value: "Membuat akun Xray + mengirim detail (.txt). **Admin only**", inline: false },
        { name: "/del", value: "Hapus akun via list+pilih+confirm. Atau isi protocol+username untuk confirm langsung. **Admin only**", inline: false },
        { name: "/accounts", value: "List akun (paging) + pilih untuk ambil ulang detail (.txt). **Admin only**", inline: false },
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
        return interaction.reply(buildPingPayload(wsMs, ipcMs));
      }

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
          const msg = quick.r && quick.r.error ? quick.r.error : "unknown error";
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

  // /accounts (admin-only)
  if (cmd === "accounts") {
    try {
      const protoFilter = String(interaction.options.getString("protocol") || "all").toLowerCase().trim();
      const page = interaction.options.getInteger("page") || 1;
      const offset = Math.max(0, (page - 1) * PAGE_SIZE);

      await interaction.deferReply({ ephemeral: true });
      const payload = await buildListMessage("acct", protoFilter, offset);

      return interaction.editReply({
        content: payload.content,
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

  // /add (admin-only)
  if (cmd === "add") {
    try {
      const protocol = interaction.options.getString("protocol");
      const username = interaction.options.getString("username");
      const days = interaction.options.getInteger("days");
      const quota_gb = interaction.options.getNumber("quota_gb");

      const v = lightValidate(protocol, username, days, quota_gb);
      if (!v.ok) return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });

      await interaction.deferReply({ ephemeral: true });

      const resp = await callBackend({ action: "add", protocol: v.protocol, username, days, quota_gb });
      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Failed: ${resp.error || "unknown error"}`);
      }

      const finalEmail = resp.username;
      const secret = resp.password || resp.uuid || "(hidden)";
      const detailPath = resp.detail_path;
      const jsonPath = resp.detail_json_path;

      const embed = new EmbedBuilder()
        .setTitle("✅ Created")
        .addFields(
          { name: "Protocol", value: v.protocol, inline: true },
          { name: "Username", value: finalEmail, inline: true },
          { name: "UUID/Pass", value: `\`${secret}\``, inline: false },
          { name: "Valid Until", value: resp.expired_at || "-", inline: true },
          { name: "Quota", value: `${quota_gb} GB`, inline: true },
        )
        .setFooter({ text: "Detail attached as .txt (XRAY ACCOUNT DETAIL)" });

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

      const content =
        `✅ Created\n` +
        `Protocol: ${v.protocol}\n` +
        `Username: ${finalEmail}\n` +
        `Valid Until: ${resp.expired_at || "-"}\n` +
        `Quota: ${quota_gb} GB\n` +
        (jsonPath ? `JSON: ${jsonPath}\n` : "");

      return interaction.editReply({ content, embeds: [embed], components: [row], files });
    } catch (e) {
      console.error(e);
      const msg = mapBackendError(e);
      if (interaction.deferred) return interaction.editReply(`❌ ${msg}`);
      return interaction.reply({ content: `❌ ${msg}`, ephemeral: true });
    }
  }

  // /del (admin-only) — two modes
  if (cmd === "del") {
    const protocolOpt = interaction.options.getString("protocol"); // may be null
    const usernameOpt = interaction.options.getString("username"); // may be null
    const page = interaction.options.getInteger("page") || 1;

    // Mode B: direct confirm if BOTH protocol+username provided (old behavior preserved)
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

      return interaction.reply({ content: "⚠️ Confirm delete", embeds: [embed], components: [row], ephemeral: true });
    }

    // If username provided but protocol missing => error (keep strict)
    if (!protocolOpt && usernameOpt) {
      return interaction.reply({ content: "❌ Jika ingin delete langsung, isi juga option protocol. Atau jalankan /del tanpa username untuk mode list.", ephemeral: true });
    }

    // Mode A: interactive list (default)
    try {
      const protoFilter = String(protocolOpt || "all").toLowerCase().trim();
      const offset = Math.max(0, (page - 1) * PAGE_SIZE);

      await interaction.deferReply({ ephemeral: true });
      const payload = await buildListMessage("del", protoFilter, offset);

      return interaction.editReply({
        content: payload.content,
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