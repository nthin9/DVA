// DVA HTML report. Reads the scan data embedded in the page and draws it.
// All values come from scanned files and advisories, so they are treated as
// text: nothing is ever inserted as HTML, and links are only made for
// http(s) URLs.
(function () {
  "use strict";

  var data = JSON.parse(document.getElementById("dva-data").textContent);
  var report = data.vulnerabilities;

  var COLORS = {
    affected: "--affected", unknown: "--unknown", no_matching_advisory: "--clean",
    not_checked: "--unchecked", lookup_failed: "--failed", none: "--unchecked", root: "--root"
  };
  var LABELS = {
    affected: "Affected", no_matching_advisory: "No matching advisory", unknown: "Unknown",
    not_checked: "Not checked", lookup_failed: "Lookup failed", none: "Not looked up",
    root: "Dependency file"
  };

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    if (className) { node.className = className; }
    return node;
  }

  function link(url, text) {
    if (typeof url !== "string" || !/^https?:\/\//i.test(url)) { return el("span", text || url); }
    var a = el("a", text || url);
    a.href = url;
    a.rel = "noopener noreferrer";
    a.target = "_blank";
    return a;
  }

  function fullName(identity) {
    return identity.namespace ? identity.namespace + "/" + identity.name : identity.name;
  }

  function table(headers, rows) {
    var wrap = el("div", null, "table-wrap");
    var t = el("table");
    var head = el("tr");
    headers.forEach(function (h) { head.appendChild(el("th", h)); });
    t.appendChild(head);
    rows.forEach(function (cells) {
      var tr = el("tr");
      cells.forEach(function (c) {
        var td = el("td");
        if (c instanceof Node) { td.appendChild(c); } else { td.textContent = c === null ? "" : String(c); }
        tr.appendChild(td);
      });
      t.appendChild(tr);
    });
    wrap.appendChild(t);
    return wrap;
  }

  function when(value) { return value ? value.replace("T", " ").replace(/\.\d+Z$/, " UTC") : "unknown"; }

  // Header and summary cards.
  document.getElementById("title").textContent = "DVA report: " + data.project_name;
  var sourceText = "vulnerabilities not checked";
  if (report) {
    var age = report.data_source === "live" ? "live data, " + when(report.checked_at)
      : report.data_source === "none" ? "no data available"
      : report.data_source + " data, oldest from " + when(report.oldest_data_at);
    sourceText = report.provider.toUpperCase() + " (" + age + ")";
  }
  document.getElementById("subtitle").textContent =
    "Scanned " + when(data.finished_at) + " with DVA " + data.tool_version + ". Advisory source: " + sourceText + ".";

  var o = data.overview;
  var cards = document.getElementById("cards");
  [
    ["Dependency files", data.manifests.length, ""],
    ["Packages in lockfiles", o.resolved_packages, ""],
    ["Affected", o.outcomes.affected, "affected"],
    ["No matching advisory", o.outcomes.no_matching_advisory, ""],
    ["Unknown or failed", o.outcomes.unknown + o.outcomes.lookup_failed, "unknown"],
    ["Not checked", o.outcomes.not_checked, ""]
  ].forEach(function (c) {
    var card = el("div", null, "card " + c[2]);
    card.appendChild(el("div", c[1], "n"));
    card.appendChild(el("div", c[0], "muted small"));
    cards.appendChild(card);
  });
  var result = "Dependency analysis: " + data.completion.replace(/_/g, " ") +
    ". Vulnerability check: " + data.vulnerability_status.replace(/_/g, " ") + ".";
  document.getElementById("result").textContent = result;

  // Lookups for checks and advisories.
  var advisories = {};
  var checksByNode = {};
  if (report) {
    report.advisories.forEach(function (a) { advisories[a.id] = a; });
    report.checks.forEach(function (check) {
      check.locations.forEach(function (loc) {
        if (loc.node_id) { checksByNode[loc.path + "::" + loc.node_id] = check; }
      });
    });
  }

  // Affected packages with their advisories.
  var affectedBox = document.getElementById("affected");
  var affected = report ? report.checks.filter(function (c) { return c.status === "affected"; }) : [];
  if (!affected.length) {
    affectedBox.appendChild(el("p", report ? "No package matched a known advisory." : "Vulnerabilities were not checked.", "muted"));
  }
  // Databases publish the same issue under their own ids and list each other as
  // aliases; show each issue once, led by its most informative record.
  function richness(f) {
    var a = advisories[f.advisory_id] || {};
    return (a.summary ? 1 : 0) + (a.database_severity ? 1 : 0);
  }
  function groupFindings(findings) {
    var groups = [];
    findings.slice().sort(function (x, y) { return x.advisory_id < y.advisory_id ? -1 : 1; })
      .forEach(function (f) {
        var a = advisories[f.advisory_id] || { aliases: [] };
        var names = [f.advisory_id].concat(a.aliases);
        var group = groups.find(function (g) {
          return names.some(function (n) { return g.names.indexOf(n) >= 0; });
        });
        if (group) { group.items.push(f); group.names = group.names.concat(names); }
        else { groups.push({ items: [f], names: names }); }
      });
    return groups.map(function (g) {
      return g.items.sort(function (x, y) {
        return richness(y) - richness(x) || (x.advisory_id < y.advisory_id ? -1 : 1);
      });
    });
  }

  affected.forEach(function (check) {
    groupFindings(check.findings).forEach(function (group) {
      var copies = group.slice(1).map(function (f) { return f.advisory_id; });
      var fixed = [], last = [];
      group.forEach(function (f) {
        f.fixed_versions.forEach(function (v) { if (fixed.indexOf(v) < 0) { fixed.push(v); } });
        f.last_affected.forEach(function (v) { if (last.indexOf(v) < 0) { last.push(v); } });
      });
      var finding = { advisory_id: group[0].advisory_id, fixed_versions: fixed, last_affected: last };
      var a = advisories[finding.advisory_id] || { id: finding.advisory_id, aliases: [], references: [], severities: [] };
      var box = el("div", null, "advisory");
      box.appendChild(el("h3", fullName(check.identity) + " " + check.version + " - " + a.id));
      if (a.summary) { box.appendChild(el("p", a.summary)); }
      var facts = el("ul");
      var aliases = a.aliases.filter(function (x) { return copies.indexOf(x) < 0; });
      if (aliases.length) { facts.appendChild(el("li", "Also known as: " + aliases.join(", "))); }
      if (copies.length) { facts.appendChild(el("li", "Also published as: " + copies.join(", "))); }
      var sev = [];
      if (a.database_severity) { sev.push(a.database_severity + " (rated by the database)"); }
      a.severities.forEach(function (s) { sev.push(s.type + " " + s.score); });
      if (sev.length) { facts.appendChild(el("li", "Severity: " + sev.join("; "))); }
      if (finding.fixed_versions.length) {
        facts.appendChild(el("li", "Fixed in: " + finding.fixed_versions.join(", ")));
      } else if (finding.last_affected.length) {
        facts.appendChild(el("li", "No fixed version given (last affected: " + finding.last_affected.join(", ") + ")"));
      } else {
        facts.appendChild(el("li", "No fixed version given by the advisory"));
      }
      facts.appendChild(el("li", "Found in: " + check.locations.map(function (l) { return l.path; }).join(", ")));
      box.appendChild(facts);
      if (a.details) {
        var more = el("details");
        more.appendChild(el("summary", "Advisory details"));
        var pre = el("p", a.details);
        pre.style.whiteSpace = "pre-wrap";
        more.appendChild(pre);
        box.appendChild(more);
      }
      if (a.references.length) {
        var refs = el("ul");
        a.references.slice(0, 12).forEach(function (r) {
          var li = el("li");
          li.appendChild(el("span", r.type + ": "));
          li.appendChild(link(r.url));
          refs.appendChild(li);
        });
        box.appendChild(refs);
      }
      affectedBox.appendChild(box);
    });
  });

  // Packages that couldn't be fully checked.
  var incomplete = report ? report.checks.filter(function (c) {
    return c.status === "unknown" || c.status === "lookup_failed" || c.status === "not_checked";
  }) : [];
  var incompleteBox = document.getElementById("incomplete");
  if (!incomplete.length) {
    incompleteBox.appendChild(el("p", report ? "Every package with an exact version was checked." : "Vulnerabilities were not checked.", "muted"));
  } else {
    incompleteBox.appendChild(table(["Package", "Version", "Outcome", "Reason", "Where"],
      incomplete.map(function (c) {
        return [fullName(c.identity), c.version, LABELS[c.status], c.reasons.join("; "),
          c.locations.map(function (l) { return l.path; }).join(", ")];
      })));
  }

  // Dependency files.
  document.getElementById("files").appendChild(table(["File", "Format", "Status", "Notes"],
    data.manifests.map(function (m) {
      var notes = m.diagnostics.filter(function (d) { return d.level !== "info"; })
        .map(function (d) { return d.message; });
      return [m.path, m.format_name + (m.format_version ? " " + m.format_version : ""), m.status, notes.join("; ")];
    })));

  document.getElementById("footer").textContent =
    "Generated by DVA " + data.tool_version + " (report format " + data.schema_version +
    "). The graph uses Cytoscape.js, MIT License, Copyright (c) 2016-2026 The Cytoscape Consortium.";

  // Legend and graph.
  var legend = document.getElementById("legend");
  ["root", "affected", "unknown", "lookup_failed", "no_matching_advisory", "not_checked"].forEach(function (s) {
    var item = el("span", LABELS[s]);
    item.style.setProperty("--dot", css(COLORS[s]));
    legend.appendChild(item);
  });

  var graphBox = document.getElementById("graph");
  var details = document.getElementById("details");
  if (data.graph.omitted) {
    graphBox.appendChild(el("p", "The graph has " + data.graph.omitted +
      " nodes, too many to draw. The tables below list everything.", "muted"));
    return;
  }
  if (!data.graph.nodes.length) {
    graphBox.appendChild(el("p", "No dependencies to draw.", "muted"));
    return;
  }
  var elements = data.graph.nodes.map(function (n) {
    return { data: { id: n.id, label: n.label, kind: n.kind, status: n.status, file: n.file || null } };
  }).concat(data.graph.edges.map(function (e, i) {
    return { data: { id: "e" + i, source: e.source, target: e.target } };
  }));
  var text = css("--text");
  var cy = cytoscape({
    container: graphBox,
    elements: elements,
    wheelSensitivity: 0.3,
    style: [
      { selector: "node", style: {
        "label": "data(label)", "font-size": 10, "color": text, "text-valign": "bottom",
        "text-margin-y": 4, "width": 14, "height": 14, "background-color": css("--unchecked"),
        "text-wrap": "ellipsis", "text-max-width": 110,
        // Ordinary labels appear once zoomed in far enough to read them.
        "min-zoomed-font-size": 9 } },
      { selector: "node[kind = 'root']", style: { "shape": "round-rectangle", "width": 24, "height": 16,
        "background-color": css("--root"), "font-weight": "bold", "min-zoomed-font-size": 0,
        "text-max-width": 220 } },
      { selector: "node[status = 'affected']", style: { "background-color": css("--affected"),
        "width": 20, "height": 20, "font-weight": "bold", "min-zoomed-font-size": 0 } },
      { selector: "node[status = 'unknown']", style: { "background-color": css("--unknown") } },
      { selector: "node[status = 'lookup_failed']", style: { "background-color": css("--failed") } },
      { selector: "node[status = 'no_matching_advisory']", style: { "background-color": css("--clean") } },
      { selector: "edge", style: { "width": 1, "line-color": css("--line"), "target-arrow-color": css("--line"),
        "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier" } },
      { selector: ":selected", style: { "border-width": 3, "border-color": text } }
    ],
    layout: { name: "breadthfirst", directed: true, spacingFactor: 1.5,
      roots: data.graph.nodes.filter(function (n) { return n.kind === "root"; }).map(function (n) { return n.id; }) }
  });

  cy.on("tap", "node", function (event) {
    var node = event.target.data();
    details.textContent = "";
    details.appendChild(el("h3", node.label));
    details.appendChild(el("p", LABELS[node.status] || node.status, "badge"));
    if (node.file) { details.appendChild(el("p", "From " + node.file, "muted small")); }
    var check = checksByNode[node.id];
    if (check) {
      if (check.findings.length) {
        var list = el("ul");
        check.findings.forEach(function (f) {
          var a = advisories[f.advisory_id] || {};
          var fix = f.fixed_versions.length ? " (fixed in " + f.fixed_versions.join(", ") + ")" : " (no fixed version given)";
          list.appendChild(el("li", f.advisory_id + (a.summary ? ": " + a.summary : "") + fix));
        });
        details.appendChild(list);
      }
      check.reasons.forEach(function (r) { details.appendChild(el("p", r, "muted small")); });
    }
    var incoming = event.target.incomers("node").map(function (n) { return n.data("label"); });
    if (incoming.length) { details.appendChild(el("p", "Required by: " + incoming.join(", "), "small")); }
  });
})();
