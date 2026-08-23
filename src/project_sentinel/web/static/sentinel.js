/* Project Sentinel — hành vi của bảng điều khiển.
 *
 * Một quy tắc chi phối cả file: mọi chuyển động trên màn hình phải tương ứng
 * với một tiến triển có thật mà máy chủ vừa báo. Không có tiến triển thì không
 * có chuyển động. Vòng lặp dưới đây vì thế không chỉ vẽ lại trạng thái, nó còn
 * tự dừng khi máy chủ nói lần chạy đã im lặng quá ngân sách của bước đang chạy.
 */
(function () {
  "use strict";

  var POLL_MS = 700;
  var POLL_MS_AFTER_ERROR = 1500;
  var MAX_CONSECUTIVE_ERRORS = 5;
  var LOG_TAIL_CAP = 200;

  /* ── Tiện ích ────────────────────────────────────────────────────────── */

  function $(id) {
    return document.getElementById(id);
  }

  function setText(el, value) {
    if (el && el.textContent !== String(value)) {
      el.textContent = String(value);
      return true;
    }
    return false;
  }

  function toneOf(state) {
    if (state === "DONE") return "ok";
    if (state === "FAILED" || state === "REJECTED") return "bad";
    return "live";
  }

  /* ── Số lượng đang chờ duyệt, hiện ngay trên thanh lệnh ──────────────── */

  function watchApprovalQueue() {
    var badge = $("gate-count");
    if (!badge) return;

    function paint(count) {
      if (!count) {
        badge.textContent = "";
        badge.removeAttribute("class");
        return;
      }
      badge.textContent = String(count);
      badge.className = "tab-count";
    }

    if (typeof window.SENTINEL_APPROVAL_COUNT === "number") {
      paint(window.SENTINEL_APPROVAL_COUNT);
    }

    function tick() {
      fetch("/api/approvals")
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (data && data.pending) paint(data.pending.length);
        })
        .catch(function () { /* thanh lệnh im lặng chịu lỗi, không phá trang */ })
        .then(function () { window.setTimeout(tick, 4000); });
    }
    window.setTimeout(tick, 1500);
  }

  /* ── Tab bằng chứng ──────────────────────────────────────────────────── */

  function wireTabs() {
    var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab[role='tab']"));
    if (!tabs.length) return;

    function nameOf(tab) {
      return tab.id.replace(/^tab-/, "");
    }

    function select(tab, remember) {
      tabs.forEach(function (other) {
        var selected = other === tab;
        other.setAttribute("aria-selected", selected ? "true" : "false");
        other.tabIndex = selected ? 0 : -1;
        var panel = $(other.getAttribute("aria-controls"));
        if (panel) panel.hidden = !selected;
      });
      // Ghi vào hash để một tab cụ thể dán được vào chat hoặc đặt bookmark —
      // và để trang nạp lại khi lần chạy xong không kéo người xem về tab đầu.
      if (remember && window.history && window.history.replaceState) {
        window.history.replaceState(null, "", "#" + nameOf(tab));
      }
    }

    tabs.forEach(function (tab, index) {
      tab.tabIndex = tab.getAttribute("aria-selected") === "true" ? 0 : -1;
      tab.addEventListener("click", function () { select(tab, true); });
      tab.addEventListener("keydown", function (event) {
        var step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
        if (!step) return;
        event.preventDefault();
        var next = tabs[(index + step + tabs.length) % tabs.length];
        select(next, true);
        next.focus();
      });
    });

    var wanted = window.location.hash.replace(/^#/, "");
    if (wanted) {
      var target = tabs.filter(function (tab) { return nameOf(tab) === wanted; })[0];
      if (target) select(target, false);
    }
  }

  /* ── Terminal ────────────────────────────────────────────────────────── */

  function makeTerminal() {
    var body = $("terminal-body");
    var autoscroll = $("autoscroll");
    if (!body) return null;

    var painted = body.querySelectorAll(".tline").length;

    function lineNode(entry, fresh) {
      var row = document.createElement("div");
      row.className = fresh ? "tline fresh" : "tline";
      row.setAttribute("data-level", entry.level || "info");

      var step = document.createElement("span");
      step.className = "tline-step";
      step.textContent = entry.step || "system";

      var message = document.createElement("span");
      message.className = "tline-msg";
      message.textContent = entry.message || "";

      row.appendChild(step);
      row.appendChild(message);
      return row;
    }

    function scrollIfWanted() {
      if (autoscroll && autoscroll.checked) body.scrollTop = body.scrollHeight;
    }

    return {
      render: function (lines) {
        if (!lines) return;
        // Nối thêm khi chỉ có dòng mới, để hiệu ứng chỉ chạy trên dòng vừa tới.
        // Khi nhật ký đã chạm trần cắt đuôi thì mảng bị trượt, lúc đó vẽ lại cả khối.
        var canAppend = lines.length > painted && lines.length < LOG_TAIL_CAP;
        if (canAppend) {
          var fragment = document.createDocumentFragment();
          for (var i = painted; i < lines.length; i += 1) {
            fragment.appendChild(lineNode(lines[i], true));
          }
          var placeholder = body.querySelector(".terminal-empty");
          if (placeholder) placeholder.remove();
          body.appendChild(fragment);
        } else if (lines.length !== painted) {
          body.textContent = "";
          lines.forEach(function (entry) { body.appendChild(lineNode(entry, false)); });
        } else {
          return;
        }
        painted = lines.length;
        scrollIfWanted();
      },
      bottom: scrollIfWanted
    };
  }

  /* ── Đường ray ───────────────────────────────────────────────────────── */

  function paintStations(steps, state) {
    var stations = document.querySelectorAll("#rail .station");
    if (!stations.length || !steps) return;

    var isTerminal = (state === "DONE" || state === "FAILED" || state === "REJECTED");

    steps.forEach(function (step, index) {
      var station = stations[index];
      if (!station) return;

      var status = step.status;
      // Dừng ở cổng phê duyệt không phải là "đang chạy": không có gì chuyển
      // động, hệ thống đang đợi một con người. Hai việc đó phải trông khác nhau.
      if (state === "AWAITING_APPROVAL" && step.name === "approval") status = "waiting";

      // Khi toàn bộ lần chạy đã hoàn thành (DONE/FAILED/REJECTED), không bước nào được giữ trạng thái 'running'
      if (isTerminal) {
        if (state === "DONE" && (status === "running" || status === "pending")) {
          status = "done";
        } else if (status === "running") {
          status = "failed";
        }
      }

      var previous = station.getAttribute("data-status");
      if (previous !== status) {
        station.setAttribute("data-status", status);
        if (status === "done" && previous === "running") {
          station.classList.add("just-done");
          window.setTimeout(function () { station.classList.remove("just-done"); }, 500);
        }
      }

      var time = station.querySelector(".station-time");
      if (time) {
        setText(time, step.elapsed_ms ? (step.elapsed_ms / 1000).toFixed(1) + "s" : "");
      }
    });
  }

  /* ── Vòng lặp chính ──────────────────────────────────────────────────── */

  function runConsole() {
    var root = $("console");
    if (!root) return;

    var runId = root.getAttribute("data-run-id");
    var wasTerminal = root.getAttribute("data-terminal") === "true";
    var runCreatedAt = root.getAttribute("data-created-at");
    var startTimeMs = runCreatedAt ? new Date(runCreatedAt).getTime() : Date.now();
    var liveTimer = null;

    var terminal = makeTerminal();
    var lamp = $("lamp");
    var idleMeter = $("idle-meter");
    var idleValue = $("idle-value");
    var idleBudget = $("idle-budget");
    var clock = $("clock");
    var stallSlot = $("stall-slot");
    var errorSlot = $("error-slot");
    var gateSlot = $("gate-slot");

    var timer = null;
    var errorStreak = 0;
    var stopped = false;
    var lastState = lamp ? lamp.textContent.trim() : "";

    var readouts = {
      findings_total: $("m-findings"),
      requests_total: $("m-requests"),
      approvals_approved: $("m-approved"),
      approvals_rejected: $("m-rejected")
    };

    if (terminal) terminal.bottom();

    function startLiveClock() {
      if (liveTimer || startTimeMs <= 0) return;
      liveTimer = window.setInterval(function () {
        if (stopped || wasTerminal) {
          window.clearInterval(liveTimer);
          liveTimer = null;
          return;
        }
        var now = Date.now();
        var elapsedSec = Math.max(0, (now - startTimeMs) / 1000);
        if (clock) setText(clock, elapsedSec.toFixed(1));
      }, 100);
    }

    function stopLiveClock(finalMs) {
      if (liveTimer) {
        window.clearInterval(liveTimer);
        liveTimer = null;
      }
      if (clock && finalMs !== undefined && finalMs !== null) {
        setText(clock, (finalMs / 1000).toFixed(1));
      }
    }

    function halt() {
      stopped = true;
      stopLiveClock();
      if (timer) window.clearTimeout(timer);
      document.documentElement.classList.add("is-stalled");
    }

    function showStall(title, detail) {
      halt();
      if (!stallSlot || stallSlot.querySelector(".notice")) return;

      var notice = document.createElement("div");
      notice.className = "notice";
      notice.setAttribute("data-tone", "bad");

      var glyph = document.createElement("span");
      glyph.className = "notice-glyph";
      glyph.setAttribute("aria-hidden", "true");
      glyph.textContent = "⏱";

      var box = document.createElement("div");
      var heading = document.createElement("strong");
      heading.textContent = title;
      var text = document.createElement("p");
      text.textContent = detail;

      var retry = document.createElement("button");
      retry.type = "button";
      retry.className = "btn";
      retry.style.marginTop = "0.6rem";
      retry.textContent = "Theo dõi lại";
      retry.addEventListener("click", function () {
        notice.remove();
        document.documentElement.classList.remove("is-stalled");
        stopped = false;
        errorStreak = 0;
        startLiveClock();
        poll();
      });

      box.appendChild(heading);
      box.appendChild(text);
      box.appendChild(retry);
      notice.appendChild(glyph);
      notice.appendChild(box);
      stallSlot.appendChild(notice);
    }

    function paintError(message) {
      if (!errorSlot) return;
      if (!message) {
        errorSlot.textContent = "";
        return;
      }
      if (errorSlot.querySelector(".notice")) return;

      var notice = document.createElement("div");
      notice.className = "notice";
      notice.setAttribute("data-tone", "bad");

      var glyph = document.createElement("span");
      glyph.className = "notice-glyph";
      glyph.setAttribute("aria-hidden", "true");
      glyph.textContent = "✕";

      var box = document.createElement("div");
      var label = document.createElement("strong");
      label.textContent = "Lần chạy hỏng: ";
      box.appendChild(label);
      box.appendChild(document.createTextNode(message));

      notice.appendChild(glyph);
      notice.appendChild(box);
      errorSlot.appendChild(notice);
    }

    function paintReadouts(metrics, state) {
      if (!metrics) return;
      Object.keys(readouts).forEach(function (key) {
        var el = readouts[key];
        if (!el || metrics[key] === undefined) return;
        if (setText(el, metrics[key])) {
          el.classList.remove("tick");
          void el.offsetWidth;
          el.classList.add("tick");
        }
      });
      var isTerminal = (state === "DONE" || state === "FAILED" || state === "REJECTED");
      if (isTerminal || state === "AWAITING_APPROVAL") {
        stopLiveClock(metrics.total_elapsed_ms);
      } else {
        startLiveClock();
      }
    }

    function finish() {
      stopLiveClock();
      var wrap = $("railwrap");
      if (wrap) wrap.classList.add("sweep");
      document.querySelectorAll("#rail .station[data-status='running']").forEach(function (el) {
        el.setAttribute("data-status", "done");
      });
      // Các tab bằng chứng do máy chủ dựng. Nạp lại một lần để chúng có nội
      // dung thật, thay vì dựng lại toàn bộ báo cáo bằng JavaScript.
      window.setTimeout(function () { window.location.reload(); }, 600);
    }

    function apply(data) {
      if (lamp) {
        setText(lamp, data.state);
        lamp.setAttribute("data-tone", toneOf(data.state));
      }

      if (idleMeter) {
        var hide = data.terminal || data.waiting_for_human;
        idleMeter.hidden = !!hide;
        if (!hide) {
          setText(idleValue, Math.round(data.idle_seconds || 0));
          setText(idleBudget, data.stall_budget_s);
        }
      }

      paintStations(data.steps, data.state);
      paintReadouts(data.metrics, data.state);
      if (terminal) terminal.render(data.log_lines);
      paintError(data.error);

      // Máy chủ đã kết luận lần chạy im lặng quá lâu. Dừng ngay, đừng vẽ tiếp
      // một hoạt ảnh gợi ý rằng vẫn còn thứ gì đó đang chạy.
      if (data.stalled) {
        showStall(
          "Không thấy tiến triển",
          "Bước " + (data.running_step || "?") + " im lặng " +
            Math.round(data.idle_seconds) + " giây, vượt ngưỡng " +
            data.stall_budget_s + " giây. Đã dừng theo dõi và tắt mọi hiệu ứng " +
            "đang chạy. Kiểm tra log của container rồi bấm Theo dõi lại."
        );
        return;
      }

      // Pipeline vừa dừng ở cổng phê duyệt: nạp lại để máy chủ dựng thẻ duyệt
      // ngay tại chỗ, người xem không phải rời trang.
      if (data.state === "AWAITING_APPROVAL" && lastState !== "AWAITING_APPROVAL") {
        if (gateSlot && !gateSlot.querySelector(".gate")) {
          window.location.reload();
          return;
        }
      }
      lastState = data.state;

      if (data.terminal) {
        if (!wasTerminal) finish();
        stopped = true;
        return;
      }

      timer = window.setTimeout(poll, POLL_MS);
    }

    function poll() {
      if (stopped) return;
      fetch("/api/runs/" + encodeURIComponent(runId))
        .then(function (response) {
          if (!response.ok) throw new Error("HTTP " + response.status);
          return response.json();
        })
        .then(function (data) {
          errorStreak = 0;
          apply(data);
        })
        .catch(function () {
          errorStreak += 1;
          if (errorStreak >= MAX_CONSECUTIVE_ERRORS) {
            showStall(
              "Mất liên lạc với máy chủ",
              "Đã thử " + MAX_CONSECUTIVE_ERRORS + " lần liên tiếp mà không nhận " +
                "được trả lời. Đã dừng theo dõi để màn hình không hiển thị một " +
                "trạng thái đã cũ."
            );
            return;
          }
          timer = window.setTimeout(poll, POLL_MS_AFTER_ERROR);
        });
    }

    if (root.getAttribute("data-stalled") === "true") {
      halt();
      showStall(
        "Không thấy tiến triển",
        "Máy chủ báo lần chạy này đã im lặng quá ngân sách của bước đang chạy. " +
          "Không theo dõi tiếp."
      );
      return;
    }

    if (!wasTerminal) {
      startLiveClock();
      timer = window.setTimeout(poll, POLL_MS);
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    watchApprovalQueue();
    wireTabs();
    runConsole();
  });
})();
