// The hero replays assets/from-tree/session.json, a session site/build.py ran
// against a real saltlick instance, one request per screen. The last screen is
// the reader's checks, computed now in this browser from the bytes the directory
// served: the package's SHA-256 against the pointer's package_sha256, and the
// Ed25519 signatures under the key the two parties read aloud (where the browser
// supports Ed25519).
(function () {
  "use strict";

  document.querySelectorAll("button.copy").forEach(function (b) {
    b.addEventListener("click", function () {
      var text = document.getElementById(b.dataset.copy).textContent;
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(function () {
        b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1600);
      });
    });
  });

  var term = document.getElementById("term"), svg = document.getElementById("actors");
  if (!term || !window.fetch || !window.crypto || !crypto.subtle) return;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var pkt = document.getElementById("pkt"), partyLabel = document.querySelector("#a-party text");

  function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join(""); }
  function b64(s) { var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  // RFC 8785 for these documents: members sorted, no whitespace (they hold only strings, booleans and arrays).
  function canon(v) {
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    if (v && typeof v === "object") return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canon(v[k]); }).join(",") + "}";
    return JSON.stringify(v);
  }
  function verify(keyB64, doc) {
    var d = JSON.parse(doc), sig = d.signature; delete d.signature;
    return crypto.subtle.importKey("raw", b64(keyB64), { name: "Ed25519" }, false, ["verify"])
      .then(function (k) { return crypto.subtle.verify({ name: "Ed25519" }, k, b64(sig), new TextEncoder().encode(canon(d))); });
  }

  fetch("assets/from-tree/session.json").then(function (r) { return r.json(); }).then(function (S) {
    var host = "https://" + S.host, steps = S.steps;
    var pointer = steps[4].body, pkg = steps[5].body, ptr = JSON.parse(pointer);

    var checks = crypto.subtle.digest("SHA-256", new TextEncoder().encode(pkg)).then(function (h) {
      var got = "sha256:" + hex(h), res = { got: got, want: ptr.package_sha256 };
      return Promise.all([verify(S.key_read_aloud, pkg), verify(S.key_read_aloud, pointer)])
        .then(function (v) { res.sig = v; return res; }, function () { res.sig = null; return res; });
    });

    function body(s) {
      var j; try { j = JSON.parse(s.body); } catch (e) { j = null; }
      var st = '<span class="' + (s.status < 300 ? "s2" : "s4") + '">HTTP ' + s.status + "</span>";
      if (s.method === "GET") return [st, esc(s.body), '<span class="adv">X-Saltlick-Advisory: ' + esc(s.advisory) + "</span>"];
      if (j && j.error) return [st + "  " + esc(j.error)];
      if (j && j.kind) return [st + "  kind " + esc(j.kind) + "  bytes " + j.bytes, "      sha256 " + esc(j.sha256)];
      if (j) return [st + "  bound_key " + esc(j.bound_key) + "  first_use " + j.first_use, '<span class="adv">' + esc(j.advisory) + "</span>"];
      return [st];
    }
    function screen(i) {
      var s = steps[i], lines = ['<span class="rd"># ' + (i + 1) + "/" + steps.length + "  " + esc(s.who === "other" ? "someone else" : s.who === "party" ? "party xaa" : "a reader") + ": " + esc(s.title) + "</span>"];
      var cmd = "$ curl" + (s.method === "GET" ? " " : " -X " + s.method + " ") + host + s.path;
      if (s.sent) cmd += " \\\n    --data-binary @" + s.sent;
      lines.push('<span class="cmdl">' + esc(cmd) + "</span>");
      return lines.concat(body(s)).join("\n");
    }
    function checkScreen(c) {
      var L = ['<span class="rd"># the reader\'s checks, computed now in this browser; the directory takes no part</span>',
        "sha256 of the package served   " + esc(c.got),
        "package_sha256 in the pointer  " + esc(c.want),
        "digest                         " + (c.got === c.want ? '<span class="ok">match</span>' : '<span class="no">differs</span>')];
      if (c.sig) {
        L.push("package signature, Ed25519    " + (c.sig[0] ? '<span class="ok">valid</span>' : '<span class="no">invalid</span>') + "  under the key read aloud");
        L.push("pointer signature, Ed25519    " + (c.sig[1] ? '<span class="ok">valid</span>' : '<span class="no">invalid</span>'));
      } else {
        L.push("signatures                     this browser has no Ed25519; README shows the openssl check");
      }
      L.push("key read aloud                 " + esc(S.key_read_aloud));
      return L.join("\n");
    }

    function actors(i) {
      ["a-party", "a-dir", "a-reader"].forEach(function (id) { document.getElementById(id).classList.remove("on"); });
      ["wl", "wr"].forEach(function (id) { document.getElementById(id).classList.remove("on"); });
      partyLabel.textContent = "party xaa";
      pkt.setAttribute("cx", -20); pkt.classList.remove("bad");
      if (i === null) { document.getElementById("a-reader").classList.add("on"); return; }
      var s = steps[i], left = s.who !== "reader";
      if (s.who === "other") partyLabel.textContent = "another key";
      document.getElementById(left ? "a-party" : "a-reader").classList.add("on");
      document.getElementById("a-dir").classList.add("on");
      document.getElementById(left ? "wl" : "wr").classList.add("on");
      if (reduce) return;
      var from = left ? 122 : 398, to = left ? 198 : 322, t0 = performance.now();
      (function move(now) {
        var u = Math.min(1, (now - t0) / 700);
        if (s.method === "GET") { var back = u > .5; pkt.setAttribute("cx", back ? to + (from - to) * (u - .5) * 2 : from + (to - from) * u * 2); }
        else pkt.setAttribute("cx", from + (to - from) * u);
        if (u >= .5 && s.status >= 400) pkt.classList.add("bad");
        if (u < 1) requestAnimationFrame(move);
      })(t0);
    }

    if (reduce) {
      checks.then(function (c) { actors(null); term.innerHTML = checkScreen(c); });
      return;
    }
    var i = 0;
    (function next() {
      if (i < steps.length) {
        actors(i); term.innerHTML = screen(i); i++;
        setTimeout(next, 3800);
      } else {
        checks.then(function (c) { actors(null); term.innerHTML = checkScreen(c); });
        i = 0; setTimeout(next, 6500);
      }
    })();
  }).catch(function () {});
})();
