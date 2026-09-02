/* The sliders switch between results the scanner already produced at build time: the
   embedded data holds, for every window length, the peak each source reached and where
   that peak began. The only thing computed here is the comparison the detector itself
   makes — peak >= threshold — so the page cannot show a detection Python would not. */
(function () {
  "use strict";

  var data = JSON.parse(document.getElementById("scan-data").textContent);
  var chart = document.getElementById("window-chart");
  var thresholdInput = document.getElementById("threshold");
  var windowInput = document.getElementById("window");
  if (!data || !chart || !thresholdInput || !windowInput) return;

  document.documentElement.classList.add("js");

  var thresholdOut = document.getElementById("threshold-value");
  var windowOut = document.getElementById("window-value");
  var verdictLine = document.getElementById("verdict-line");
  var tableBody = document.getElementById("flagged-body");

  function peaksFor(windowSeconds) {
    return data.peaks[String(windowSeconds)] || {};
  }

  function scaleFor(ip) {
    var span = data.geometry.spans[ip] || 1;
    return data.geometry.width / span;
  }

  // Looked up once by their data-row value rather than through an attribute selector per
  // redraw: an IPv6 address is full of characters a selector would have to escape.
  var lanesByIp = {};
  Array.prototype.forEach.call(chart.querySelectorAll("[data-row]"), function (group) {
    lanesByIp[group.getAttribute("data-row")] = {
      row: group,
      band: group.querySelector("[data-band]"),
      verdict: group.querySelector("[data-verdict]"),
    };
  });

  function updateLane(lane, peaks, threshold, windowSeconds) {
    var nodes = lanesByIp[lane.ip];
    if (!nodes) return false;
    var entry = peaks[lane.ip];
    var row = nodes.row;
    var band = nodes.band;
    var verdict = nodes.verdict;

    var peak = entry ? entry.peak : 0;
    var flagged = peak >= threshold;
    row.setAttribute("class", flagged ? "row flagged" : "row");

    if (band) {
      if (entry) {
        var scale = scaleFor(lane.ip);
        var x = data.geometry.x + entry.start * scale;
        var width = Math.min(windowSeconds * scale, data.geometry.x + data.geometry.width - x);
        band.setAttribute("x", x.toFixed(1));
        band.setAttribute("width", Math.max(width, 2).toFixed(1));
        band.style.display = "";
      } else {
        band.style.display = "none";
      }
    }
    if (verdict) {
      var label = data.windowLabels[String(windowSeconds)];
      verdict.textContent = entry
        ? peak + " in " + label + (flagged ? " ≥ " : " < ") + threshold
        : "no failures";
    }
    return flagged;
  }

  function cell(text, className) {
    var td = document.createElement("td");
    td.textContent = text;
    if (className) td.className = className;
    return td;
  }

  function updateTable(flagged, peaks) {
    if (!tableBody) return;
    tableBody.textContent = "";
    if (!flagged.length) {
      var empty = document.createElement("tr");
      var td = cell("No source reaches the threshold at this setting.", "empty");
      td.colSpan = 6;
      empty.appendChild(td);
      tableBody.appendChild(empty);
      return;
    }
    flagged.forEach(function (lane) {
      var tr = document.createElement("tr");
      tr.className = "flagged";
      tr.appendChild(cell(lane.ip, "ip"));
      tr.appendChild(cell(String(peaks[lane.ip].peak), "num"));
      tr.appendChild(cell(String(lane.failures), "num"));
      tr.appendChild(cell(String(lane.users), "num"));
      tr.appendChild(cell(lane.first));
      tr.appendChild(cell(lane.last));
      tableBody.appendChild(tr);
    });
  }

  function apply() {
    var threshold = data.thresholds[Number(thresholdInput.value)];
    var windowSeconds = data.windows[Number(windowInput.value)];
    var peaks = peaksFor(windowSeconds);

    var flagged = data.lanes.filter(function (lane) {
      return updateLane(lane, peaks, threshold, windowSeconds);
    });
    // Same order the CLI prints: densest window first, total failures breaking the tie.
    flagged.sort(function (a, b) {
      return peaks[b.ip].peak - peaks[a.ip].peak || b.failures - a.failures;
    });

    thresholdOut.textContent = String(threshold);
    windowOut.textContent = data.windowLabels[String(windowSeconds)];
    if (verdictLine) {
      var strong = document.createElement("strong");
      strong.textContent = flagged.length + (flagged.length === 1 ? " source" : " sources");
      verdictLine.textContent = "";
      verdictLine.appendChild(document.createTextNode("At these settings the scanner flags "));
      verdictLine.appendChild(strong);
      verdictLine.appendChild(
        document.createTextNode(" of the " + data.lanes.length + " in this log.")
      );
    }
    updateTable(flagged, peaks);
  }

  thresholdInput.addEventListener("input", apply);
  windowInput.addEventListener("input", apply);
  apply();
})();
