/* ═══════════════════════════════════════════════════════════════════════════
   Q-SHIELD COMMAND CENTER — Frontend Logic
   Polls /api/packets + /api/security every 1 s, drives all dashboard panels.
   ═══════════════════════════════════════════════════════════════════════════ */

(function () {
    "use strict";

    // ── State ────────────────────────────────────────────────────────────
    let lastSeq = -1;
    let bpmHistory = [];
    let accelHistory = [];
    let trailCoords = [];
    let knownPacketSeqs = new Set();
    let map = null, marker = null, trail = null;
    let mapReady = false, tilesLoaded = false;
    let demoRunning = false;
    let lastPacketTime = 0;

    const MAX_BPM   = 60;
    const MAX_ACCEL  = 40;
    const MAX_TRAIL  = 30;
    const POLL_MS    = 1000;
    const STALE_MS   = 5000;

    const $ = (s) => document.querySelector(s);
    const $$ = (s) => document.querySelectorAll(s);

    // ── Init ─────────────────────────────────────────────────────────────
    document.addEventListener("DOMContentLoaded", () => {
        startClock();
        initMap();
        initPipelineTooltips();
        checkDemoStatus();
        pollLoop();
    });

    // ═════════════════════════════════════════════════════════════════════
    // UTC Clock
    // ═════════════════════════════════════════════════════════════════════
    function startClock() {
        const el = $("#utc-clock");
        const tick = () => { el.textContent = new Date().toISOString().slice(11, 19) + " UTC"; };
        tick();
        setInterval(tick, 1000);
    }

    // ═════════════════════════════════════════════════════════════════════
    // Link status
    // ═════════════════════════════════════════════════════════════════════
    function updateLinkStatus() {
        const el = $("#link-status");
        const elapsed = Date.now() - lastPacketTime;
        if (lastPacketTime === 0 || elapsed > STALE_MS) {
            el.className = "link-status stale";
            el.querySelector(".link-label").textContent = "STALE";
        } else {
            el.className = "link-status live";
            el.querySelector(".link-label").textContent = "LIVE";
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Demo toggle
    // ═════════════════════════════════════════════════════════════════════
    window.toggleDemo = async function () {
        const btn = $("#demo-toggle");
        try {
            if (demoRunning) {
                await fetch("/api/demo/stop", { method: "POST" });
                demoRunning = false;
                btn.classList.remove("active");
            } else {
                await fetch("/api/demo/start", { method: "POST" });
                demoRunning = true;
                btn.classList.add("active");
            }
        } catch (e) { console.error("Demo toggle failed", e); }
    };

    async function checkDemoStatus() {
        try {
            const res = await fetch("/api/demo/status");
            const data = await res.json();
            demoRunning = data.running;
            if (demoRunning) $("#demo-toggle").classList.add("active");
        } catch (e) { /* ignore */ }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Attack console
    // ═════════════════════════════════════════════════════════════════════
    window.fireAttack = async function (type) {
        const btn = document.querySelector(`.attack-btn.${type}`);
        if (btn) { btn.disabled = true; btn.classList.add("fired"); }
        try {
            await fetch(`/api/attack/${type}`, { method: "POST" });
        } catch (e) { console.error("Attack failed", e); }
        setTimeout(() => {
            if (btn) { btn.disabled = false; btn.classList.remove("fired"); }
        }, type === "flood" ? 3000 : 800);
    };

    window.toggleJamming = async function (start) {
        try {
            if (start) {
                await fetch("/api/jamming/start", { method: "POST" });
            } else {
                await fetch("/api/jamming/stop", { method: "POST" });
            }
        } catch (e) { console.error("Jamming toggle failed", e); }
    };

    // ═════════════════════════════════════════════════════════════════════
    // Polling loop
    // ═════════════════════════════════════════════════════════════════════
    async function pollLoop() {
        try {
            const [pktsRes, evtsRes, secRes] = await Promise.all([
                fetch("/api/packets"),
                fetch("/api/events"),
                fetch("/api/security"),
            ]);
            const packets = await pktsRes.json();
            const events  = await evtsRes.json();
            const security = await secRes.json();

            if (packets && packets.length > 0) {
                const latest = packets[packets.length - 1];
                let hasNew = false;
                for (const p of packets) {
                    if (!knownPacketSeqs.has(p.seq)) {
                        knownPacketSeqs.add(p.seq);
                        hasNew = true;
                    }
                }
                if (latest.seq !== lastSeq) {
                    lastPacketTime = Date.now();
                    lastSeq = latest.seq;
                    updateUnitCard(latest);
                    updateMapPanel(latest);
                    updateMotionPanel(latest);
                    updateVitalsPanel(latest);
                    if (hasNew) animatePipeline();
                }
                updatePacketFeed(packets);
            }

            if (events) updateEventLog(events);
            if (security) updateSecurityPanel(security);

        } catch (e) { /* server down */ }

        updateLinkStatus();
        setTimeout(pollLoop, POLL_MS);
    }

    // ═════════════════════════════════════════════════════════════════════
    // Pipeline animation
    // ═════════════════════════════════════════════════════════════════════
    function animatePipeline() {
        const connectors = $$(".pipeline-connector .pulse-dot");
        const nodes = $$(".pipeline-node .node-icon");
        connectors.forEach((dot, i) => {
            setTimeout(() => {
                dot.classList.remove("animate");
                void dot.offsetWidth;
                dot.classList.add("animate");
            }, i * 250);
        });
        nodes.forEach((node, i) => {
            setTimeout(() => {
                node.classList.add("pulse-active");
                setTimeout(() => node.classList.remove("pulse-active"), 500);
            }, i * 250);
        });
    }

    function initPipelineTooltips() {
        $$(".pipeline-node").forEach((node) => {
            node.addEventListener("click", () => {
                const was = node.classList.contains("show-tooltip");
                $$(".pipeline-node").forEach(n => n.classList.remove("show-tooltip"));
                if (!was) node.classList.add("show-tooltip");
            });
        });
    }

    // ═════════════════════════════════════════════════════════════════════
    // Unit Card
    // ═════════════════════════════════════════════════════════════════════
    function updateUnitCard(pkt) {
        const badge = $("#status-badge");
        const status = pkt.status || "ACTIVE";
        const priority = pkt.priority || "ROUTINE";

        badge.className = "status-badge " +
            (status === "ACTIVE" ? "active" :
             status === "DISTRESS" ? "distress" : "injured");
        badge.querySelector(".status-text").textContent = status.replace("_", " ");

        const ptag = $("#priority-tag");
        ptag.className = "priority-tag " + priority.toLowerCase();
        ptag.textContent = priority;

        $("#meta-age").textContent = timeSince(pkt.ts || pkt.server_rx);
        $("#meta-seq").textContent = "#" + (pkt.seq || 0);
        $("#meta-digest").textContent = pkt.digest || "—";

        // Verified badge
        const vbadge = $("#verified-badge");
        if (pkt.verified) {
            vbadge.classList.remove("hidden");
            vbadge.classList.add("flash");
            setTimeout(() => vbadge.classList.remove("flash"), 600);
        } else {
            vbadge.classList.add("hidden");
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Security Panel
    // ═════════════════════════════════════════════════════════════════════
    function updateSecurityPanel(sec) {
        const s = sec.stats || {};

        // Counters
        setCounter("stat-invalid-sigs", s.invalid_sigs || 0);
        setCounter("stat-replays", s.replays || 0);
        setCounter("stat-seq-gaps", s.seq_gaps || 0);
        setCounter("stat-floods", s.floods || 0);
        setCounter("stat-channel-drops", s.channel_drops || 0);

        // Channel monitor state
        const monitorEl = $("#monitor-state");
        const state = (sec.channel_state || "CALIBRATING").toLowerCase();
        monitorEl.className = "monitor-state " + state;
        monitorEl.querySelector(".monitor-text").textContent =
            (sec.channel_state || "CALIBRATING").replace("_", " ");

        // Calibration bar
        const cal = sec.calibration || { current: 0, target: 25, done: false };
        const calBar = $("#calibration-bar");
        if (cal.done) {
            calBar.classList.add("hidden");
        } else {
            calBar.classList.remove("hidden");
            const pct = Math.min(100, (cal.current / cal.target) * 100);
            $("#cal-fill").style.width = pct + "%";
            $("#cal-label").textContent = `Calibrating ${cal.current} / ${cal.target}`;
        }

        // Channel badge
        const chBadge = $("#channel-badge");
        const chLabel = $("#channel-label");
        if (sec.channel === "LORA") {
            chBadge.className = "channel-badge lora";
            chLabel.textContent = "LoRa BACKUP";
        } else {
            chBadge.className = "channel-badge primary";
            chLabel.textContent = "PRIMARY";
        }

        // LoRa status text
        const loraEl = $("#stat-lora");
        if (sec.channel === "LORA") {
            loraEl.textContent = "ACTIVE";
            loraEl.className = "sec-value sec-counter alert";
        } else {
            loraEl.textContent = "READY";
            loraEl.className = "sec-value ok";
        }

        // Jamming buttons
        const jamStartBtn = $("#jam-start-btn");
        const jamStopBtn  = $("#jam-stop-btn");
        const jamStatus   = $("#jam-status");
        if (sec.jamming) {
            jamStartBtn.disabled = true;
            jamStopBtn.disabled = false;
            jamStatus.classList.remove("hidden");
        } else {
            jamStartBtn.disabled = false;
            jamStopBtn.disabled = true;
            jamStatus.classList.add("hidden");
        }
    }

    function setCounter(id, value) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = value;
        if (value > 0) {
            el.classList.remove("ok", "none");
            el.classList.add("alert");
        } else {
            el.classList.remove("alert");
            el.classList.add("ok");
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Map Panel
    // ═════════════════════════════════════════════════════════════════════
    function initMap() {
        try {
            map = L.map("map", {
                center: [33.7548, 78.6834], zoom: 13,
                zoomControl: false, attributionControl: false,
            });
            const tiles = L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19 });
            tiles.on("tileerror", () => { if (!tilesLoaded) showMapFallback(); });
            tiles.on("load", () => { tilesLoaded = true; });
            tiles.addTo(map);

            const icon = L.divIcon({
                className: "custom-marker",
                html: '<div style="width:16px;height:16px;background:var(--accent-cyan);border:2px solid #fff;border-radius:50%;box-shadow:0 0 16px rgba(56,189,248,0.6);"></div>',
                iconSize: [16, 16], iconAnchor: [8, 8],
            });
            marker = L.marker([33.7548, 78.6834], { icon }).addTo(map);
            trail = L.polyline([], { color: "rgba(56,189,248,0.5)", weight: 2, dashArray: "4 6" }).addTo(map);
            mapReady = true;
            setTimeout(() => { if (!tilesLoaded) showMapFallback(); }, 5000);
        } catch (e) { showMapFallback(); }
    }

    function showMapFallback() {
        const mapEl = document.getElementById("map");
        const fb = $(".map-fallback");
        if (mapEl) mapEl.style.display = "none";
        if (fb) fb.style.display = "flex";
    }

    function updateMapPanel(pkt) {
        const loc = pkt.location || {};
        const lat = loc.lat || 0, lon = loc.lon || 0;
        $("#map-fix").textContent = loc.fix ? "3D FIX" : "NO FIX";
        $("#map-sats").textContent = (loc.sats || 0) + " SATS";
        $("#map-src").textContent = loc.src || "—";

        if (mapReady && map) {
            const pos = [lat, lon];
            marker.setLatLng(pos);
            map.panTo(pos, { animate: true, duration: 0.5 });
            trailCoords.push(pos);
            if (trailCoords.length > MAX_TRAIL) trailCoords = trailCoords.slice(-MAX_TRAIL);
            trail.setLatLngs(trailCoords);
        }
        $(".map-fallback .coords").textContent = lat.toFixed(6) + "°N  " + lon.toFixed(6) + "°E";
    }

    // ═════════════════════════════════════════════════════════════════════
    // Motion Panel
    // ═════════════════════════════════════════════════════════════════════
    function updateMotionPanel(pkt) {
        const m = pkt.motion || {};
        const stateEl = $("#motion-state");
        stateEl.textContent = m.state || "—";
        stateEl.className = "stat-value " +
            (m.state === "IMPACT" ? "impact" : m.state === "MOVING" ? "moving" : "still");

        $("#motion-accel").textContent = (m.accel_g || 0).toFixed(2) + "g";
        $("#motion-peak").textContent = (m.peak_g || 0).toFixed(2) + "g";

        accelHistory.push(m.accel_g || 1.0);
        if (accelHistory.length > MAX_ACCEL) accelHistory = accelHistory.slice(-MAX_ACCEL);

        drawSparkline("accel-sparkline", accelHistory, {
            min: 0, max: 4,
            color: m.state === "IMPACT" ? "#ef4444" : "#38bdf8",
            fillColor: m.state === "IMPACT" ? "rgba(239,68,68,0.1)" : "rgba(56,189,248,0.08)",
        });
    }

    // ═════════════════════════════════════════════════════════════════════
    // Vitals Panel
    // ═════════════════════════════════════════════════════════════════════
    function updateVitalsPanel(pkt) {
        const v = pkt.vitals || {};
        const bpmEl = $("#bpm-value");
        const fingerDot = $("#finger-dot");
        const fingerText = $("#finger-text");

        if (v.finger) {
            bpmEl.textContent = v.bpm || 0;
            bpmEl.className = "bpm-display";
            fingerDot.className = "finger-dot on";
            fingerText.textContent = "SENSOR ACTIVE";
            bpmHistory.push(v.bpm || 0);
        } else {
            bpmEl.textContent = "NO SIGNAL";
            bpmEl.className = "bpm-display no-finger";
            fingerDot.className = "finger-dot off";
            fingerText.textContent = "NO FINGER";
            bpmHistory.push(null);
        }
        if (bpmHistory.length > MAX_BPM) bpmHistory = bpmHistory.slice(-MAX_BPM);
        drawBPMChart("bpm-chart", bpmHistory);
    }

    // ═════════════════════════════════════════════════════════════════════
    // Canvas Charts
    // ═════════════════════════════════════════════════════════════════════
    function drawSparkline(canvasId, data, opts) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.parentElement.clientWidth;
        const h = canvas.parentElement.clientHeight;
        canvas.width = w * dpr; canvas.height = h * dpr;
        canvas.style.width = w + "px"; canvas.style.height = h + "px";
        ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
        if (data.length < 2) return;

        const min = opts.min ?? Math.min(...data);
        const max = opts.max ?? Math.max(...data);
        const range = max - min || 1;
        const step = w / (data.length - 1);

        ctx.beginPath(); ctx.moveTo(0, h);
        data.forEach((v, i) => { ctx.lineTo(i * step, h - ((v - min) / range) * (h - 4) - 2); });
        ctx.lineTo((data.length - 1) * step, h); ctx.closePath();
        ctx.fillStyle = opts.fillColor || "rgba(56,189,248,0.08)"; ctx.fill();

        ctx.beginPath();
        data.forEach((v, i) => {
            const x = i * step, y = h - ((v - min) / range) * (h - 4) - 2;
            i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        });
        ctx.strokeStyle = opts.color || "#38bdf8"; ctx.lineWidth = 1.5; ctx.stroke();

        const lx = (data.length - 1) * step;
        const ly = h - ((data[data.length - 1] - min) / range) * (h - 4) - 2;
        ctx.beginPath(); ctx.arc(lx, ly, 3, 0, Math.PI * 2);
        ctx.fillStyle = opts.color || "#38bdf8"; ctx.fill();
    }

    function drawBPMChart(canvasId, data) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.parentElement.clientWidth;
        const h = canvas.parentElement.clientHeight;
        canvas.width = w * dpr; canvas.height = h * dpr;
        canvas.style.width = w + "px"; canvas.style.height = h + "px";
        ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);

        const valid = data.filter(v => v !== null);
        if (valid.length < 2) return;
        const min = Math.max(40, Math.min(...valid) - 10);
        const max = Math.min(200, Math.max(...valid) + 10);
        const range = max - min || 1;
        const step = w / (data.length - 1);

        ctx.strokeStyle = "rgba(26,39,68,0.5)"; ctx.lineWidth = 0.5;
        for (let bpm = 60; bpm <= 160; bpm += 20) {
            const y = h - ((bpm - min) / range) * (h - 8) - 4;
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
        }

        ctx.beginPath(); let started = false;
        data.forEach((v, i) => {
            if (v === null) { started = false; return; }
            const x = i * step, y = h - ((v - min) / range) * (h - 8) - 4;
            started ? ctx.lineTo(x, y) : (ctx.moveTo(x, y), started = true);
        });
        ctx.strokeStyle = "#ef4444"; ctx.lineWidth = 2; ctx.stroke();

        ctx.beginPath(); let fs = false;
        data.forEach((v, i) => {
            if (v === null) {
                if (fs) { ctx.lineTo((i - 1) * step, h); ctx.closePath(); ctx.fillStyle = "rgba(239,68,68,0.06)"; ctx.fill(); ctx.beginPath(); fs = false; }
                return;
            }
            const x = i * step, y = h - ((v - min) / range) * (h - 8) - 4;
            if (!fs) { ctx.moveTo(x, h); ctx.lineTo(x, y); fs = true; } else { ctx.lineTo(x, y); }
        });
        if (fs) { ctx.lineTo((data.length - 1) * step, h); ctx.closePath(); ctx.fillStyle = "rgba(239,68,68,0.06)"; ctx.fill(); }

        const lv = data[data.length - 1];
        if (lv !== null) {
            const lx = (data.length - 1) * step;
            const ly = h - ((lv - min) / range) * (h - 8) - 4;
            ctx.beginPath(); ctx.arc(lx, ly, 4, 0, Math.PI * 2);
            ctx.fillStyle = "#ef4444"; ctx.fill();
            ctx.beginPath(); ctx.arc(lx, ly, 7, 0, Math.PI * 2);
            ctx.strokeStyle = "rgba(239,68,68,0.3)"; ctx.lineWidth = 1.5; ctx.stroke();
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Packet Feed
    // ═════════════════════════════════════════════════════════════════════
    function updatePacketFeed(packets) {
        const tbody = $("#packet-tbody");
        if (!tbody) return;
        const recent = packets.slice(-30).reverse();
        const existingSeqs = new Set();
        tbody.querySelectorAll("tr.pkt-row").forEach(row => existingSeqs.add(parseInt(row.dataset.seq)));

        const fragment = document.createDocumentFragment();
        recent.forEach((pkt) => {
            const tr = document.createElement("tr");
            tr.className = "pkt-row"; tr.dataset.seq = pkt.seq;
            if (!existingSeqs.has(pkt.seq)) tr.classList.add("new-row");

            const sc = pkt.status === "ACTIVE" ? "color:var(--accent-green)" :
                       pkt.status === "DISTRESS" ? "color:var(--accent-amber)" : "color:var(--accent-red)";
            const pc = pkt.priority === "CRITICAL" ? "color:var(--accent-red)" :
                       pkt.priority === "HIGH" ? "color:var(--accent-amber)" : "color:var(--accent-cyan)";
            const ts = pkt.ts ? new Date(pkt.ts).toISOString().slice(11, 19) : "—";

            tr.innerHTML = `
                <td>${pkt.seq || "—"}</td>
                <td>${ts}</td>
                <td style="${sc}">${(pkt.status || "—").replace("_", " ")}</td>
                <td style="${pc}">${pkt.priority || "—"}</td>
                <td class="digest-col">${pkt.digest || "—"}</td>`;

            const jr = document.createElement("tr");
            jr.innerHTML = `<td colspan="5" style="padding:0"><div class="packet-raw-json">${JSON.stringify(pkt, null, 2)}</div></td>`;
            tr.addEventListener("click", () => jr.querySelector(".packet-raw-json").classList.toggle("visible"));

            fragment.appendChild(tr);
            fragment.appendChild(jr);
        });
        tbody.innerHTML = "";
        tbody.appendChild(fragment);
    }

    // ═════════════════════════════════════════════════════════════════════
    // Event Log
    // ═════════════════════════════════════════════════════════════════════
    function updateEventLog(events) {
        const list = $("#event-log-list");
        if (!list) return;
        const recent = events.slice(-40).reverse();
        list.innerHTML = recent.map(evt => {
            const ts = evt.ts ? new Date(evt.ts).toISOString().slice(11, 19) : "—";
            return `<li class="level-${evt.level || 'INFO'}">
                <span class="event-time">${ts}</span>
                <span class="event-msg">${escapeHtml(evt.msg || "")}</span>
            </li>`;
        }).join("");
    }

    // ═════════════════════════════════════════════════════════════════════
    // Helpers
    // ═════════════════════════════════════════════════════════════════════
    function timeSince(iso) {
        if (!iso) return "—";
        const d = (Date.now() - new Date(iso).getTime()) / 1000;
        if (d < 0) return "0s ago";
        if (d < 60) return Math.floor(d) + "s ago";
        if (d < 3600) return Math.floor(d / 60) + "m ago";
        return Math.floor(d / 3600) + "h ago";
    }

    function escapeHtml(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }
})();
