<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#scan">{{ lang._('Scan') }}</a></li>
    <li><a data-toggle="tab" href="#hosts">{{ lang._('Interfaces') }}</a></li>
    <li><a data-toggle="tab" href="#custom">{{ lang._('Custom') }}</a></li>
    <li><a data-toggle="tab" href="#profiles">{{ lang._('Scan Profiles') }}</a></li>
</ul>

<div class="tab-content content-box tab-content">
    <div id="scan" class="tab-pane fade in active">
        <div class="content-box tab-content table-responsive">
            <table class="table table-striped __nomb">
                <tr>
                    <th colspan="2" style="vertical-align:top" class="listtopic">{{ lang._('Quick Scan') }}</th>
                </tr>
                <tr>
                    <td style="width:22%"><label for="scan_target">{{ lang._('Target') }}</label></td>
                    <td>
                        <input type="text" id="scan_target" class="form-control" placeholder="192.168.1.1 or 192.168.1.0/24" />
                    </td>
                </tr>
                <tr>
                    <td><label for="scan_profile">{{ lang._('Profile') }}</label></td>
                    <td>
                        <select id="scan_profile" class="form-control">
                            <option value="">{{ lang._('Loading profiles...') }}</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td style="width:22%; vertical-align:top">&nbsp;</td>
                    <td>
                        <input type="button" class="btn btn-primary" value="{{ lang._('Scan') }}" id="scanAct" />
                        <i id="scanAct_progress"></i>
                        <div class="progress hidden" id="scan_progress" style="margin-top:8px;">
                            <div class="progress-bar progress-bar-striped active" id="scan_progress_bar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                        </div>
                    </td>
                </tr>
            </table>
        </div>

        <pre class="hidden" id="scanOutput"></pre>
    </div>

    <div id="hosts" class="tab-pane fade in">
        <div class="content-box tab-content table-responsive">
            <table class="table table-striped __nomb">
                <tr>
                    <th colspan="2" style="vertical-align:top" class="listtopic">{{ lang._('Interface Scan') }}</th>
                </tr>
                <tr>
                    <td style="width:22%"><label for="hosts_profile">{{ lang._('Profile') }}</label></td>
                    <td>
                        <select id="hosts_profile" class="form-control">
                            <option value="">{{ lang._('Loading profiles...') }}</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td>{{ lang._('Interfaces') }}</td>
                    <td>
                        <div class="checkbox">
                            <label><input type="checkbox" id="hosts_select_all" />{{ lang._('Select all') }}</label>
                        </div>
                        <table class="table table-striped __nomb" id="interfaces_table">
                            <thead>
                                <tr>
                                    <th style="width:10%">{{ lang._('Use') }}</th>
                                    <th>{{ lang._('Interface') }}</th>
                                    <th>{{ lang._('Network') }}</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td style="width:22%; vertical-align:top">&nbsp;</td>
                    <td>
                        <input type="button" class="btn btn-primary" value="{{ lang._('Scan Networks') }}" id="hostsAct" />
                        <input type="button" class="btn btn-default" value="{{ lang._('Clear Last Scan') }}" id="hostsClear" />
                        <input type="button" class="btn btn-default" value="{{ lang._('Export JSON') }}" id="hostsExportJson" />
                        <input type="button" class="btn btn-default" value="{{ lang._('Export CSV') }}" id="hostsExportCsv" />
                        <i id="hostsAct_progress"></i>
                        <div class="progress hidden" id="hosts_progress" style="margin-top:8px;">
                            <div class="progress-bar progress-bar-striped active" id="hosts_progress_bar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                        </div>
                    </td>
                </tr>
            </table>
        </div>

        <div class="alert alert-info hidden" id="hostsInfo"></div>

        <div class="content-box tab-content table-responsive">
            <table class="table table-striped" id="hosts_table">
                <thead>
                    <tr>
                        <th style="width:18%">{{ lang._('Address') }}</th>
                        <th style="width:18%">{{ lang._('Hostname') }}</th>
                        <th style="width:14%">{{ lang._('MAC') }}</th>
                        <th style="width:14%">{{ lang._('Vendor') }}</th>
                        <th style="width:10%">{{ lang._('Status') }}</th>
                        <th>{{ lang._('Open Services') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <div id="custom" class="tab-pane fade in">
        <div class="content-box tab-content table-responsive">
            <table class="table table-striped __nomb">
                <tr>
                    <th colspan="2" style="vertical-align:top" class="listtopic">{{ lang._('Custom Command') }}</th>
                </tr>
                <tr>
                    <td style="width:22%"><label for="custom_target">{{ lang._('Target') }}</label></td>
                    <td>
                        <input type="text" id="custom_target" class="form-control" placeholder="192.168.1.1 or 192.168.1.0/24" />
                    </td>
                </tr>
                <tr>
                    <td><label for="custom_args">{{ lang._('Arguments') }}</label></td>
                    <td>
                        <textarea id="custom_args" class="form-control" rows="3" placeholder="-sS -sV -p 1-1000"></textarea>
                        <div class="help-block">{{ lang._('Enter arguments only (without nmap and target).') }}</div>
                    </td>
                </tr>
                <tr>
                    <td style="width:22%; vertical-align:top">&nbsp;</td>
                    <td>
                        <input type="button" class="btn btn-primary" value="{{ lang._('Run Command') }}" id="customAct" />
                        <i id="customAct_progress"></i>
                        <div class="progress hidden" id="custom_progress" style="margin-top:8px;">
                            <div class="progress-bar progress-bar-striped active" id="custom_progress_bar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                        </div>
                    </td>
                </tr>
            </table>
        </div>

        <pre class="hidden" id="customOutput"></pre>
    </div>

    <div id="profiles" class="tab-pane fade in">
        <div class="content-box">
            {{ partial('layout_partials/base_bootgrid_table', profileGrid + {'command_width': '150'}) }}
        </div>
        {{ partial("layout_partials/base_dialog",['fields': profileForm,'id':profileGrid['edit_dialog_id'],'label':lang._('Edit Scan Profile')]) }}
    </div>
</div>

<style>
    .nmap-service-line {
        margin-bottom: 4px;
    }
    #hostsClear,
    #hostsExportJson,
    #hostsExportCsv {
        margin-left: 6px;
    }
</style>

<script>
$(function() {
    var profileGrid = null;
    var lastResults = null;

    function updateOutput(target, text) {
        $(target).text(text || "");
        $(target).removeClass("hidden");
    }

    function escapeHtml(text) {
        return $("<div/>").text(text || "").html();
    }

    function updateHostsInfo(text) {
        if (!text) {
            return;
        }
        $("#hostsInfo").text(text).removeClass("hidden");
    }

    function buildExportFilename(extension, data) {
        var ts = new Date();
        if (data && data.generated_at) {
            var parsed = new Date(data.generated_at);
            if (!isNaN(parsed.getTime())) {
                ts = parsed;
            }
        }
        var stamp = ts.toISOString().replace(/[:]/g, "").replace(/\..+/, "");
        var profile = data && data.profile ? String(data.profile) : "scan";
        var slug = profile.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
        if (!slug) {
            slug = "scan";
        }
        return "nmap-hosts-" + slug + "-" + stamp + "." + extension;
    }

    function downloadBlob(content, filename, contentType) {
        var blob = new Blob([content], { type: contentType });
        var url = URL.createObjectURL(blob);
        var link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        setTimeout(function() {
            URL.revokeObjectURL(url);
            link.remove();
        }, 100);
    }

    function csvEscape(value) {
        if (value === null || value === undefined) {
            value = "";
        }
        var text = String(value);
        if (/[",\n\r]/.test(text)) {
            text = "\"" + text.replace(/"/g, "\"\"") + "\"";
        }
        return text;
    }

    function formatPortEntry(port) {
        if (!port) {
            return "";
        }
        var portId = port.port !== undefined && port.port !== null ? String(port.port) : "";
        var proto = port.proto ? String(port.proto) : "";
        var label = portId;
        if (proto) {
            label = label ? label + "/" + proto : proto;
        }
        var details = [];
        if (port.service) {
            details.push(port.service);
        }
        if (port.product) {
            details.push(port.product);
        }
        if (port.version) {
            details.push(port.version);
        }
        if (port.extra) {
            details.push(port.extra);
        }
        var text = label;
        if (details.length) {
            text += " " + details.join(" ");
        }
        if (port.tunnel) {
            text += " [" + port.tunnel + "]";
        }
        return text.trim();
    }

    function resultsToCsv(data) {
        var generatedAt = data && data.generated_at ? data.generated_at : "";
        var profile = data && data.profile ? data.profile : "";
        var targets = "";
        if (data && Array.isArray(data.targets)) {
            targets = data.targets.join(" ");
        } else if (data && data.targets) {
            targets = data.targets;
        }
        var hosts = data && Array.isArray(data.hosts) ? data.hosts : [];
        var lines = [];
        var header = [
            "generated_at",
            "profile",
            "targets",
            "address",
            "hostname",
            "status",
            "mac",
            "vendor",
            "open_services"
        ];
        lines.push(header.join(","));
        if (hosts.length === 0) {
            lines.push([
                generatedAt,
                profile,
                targets,
                "",
                "",
                "",
                "",
                "",
                ""
            ].map(csvEscape).join(","));
            return lines.join("\n");
        }
        hosts.forEach(function(host) {
            var services = "";
            if (host && Array.isArray(host.ports)) {
                services = host.ports.map(formatPortEntry).filter(function(item) {
                    return item !== "";
                }).join("; ");
            }
            lines.push([
                generatedAt,
                profile,
                targets,
                host.address || "",
                host.hostname || "",
                host.status || "",
                host.mac || "",
                host.vendor || "",
                services
            ].map(csvEscape).join(","));
        });
        return lines.join("\n");
    }

    var progressTimers = {};

    function updateProgress(prefix, value) {
        var bar = $("#" + prefix + "_progress_bar");
        if (!bar.length) {
            return;
        }
        bar.css("width", value + "%").attr("aria-valuenow", value).text(value + "%");
    }

    function startProgress(prefix) {
        var container = $("#" + prefix + "_progress");
        var bar = $("#" + prefix + "_progress_bar");
        if (!container.length || !bar.length) {
            return;
        }
        if (progressTimers[prefix]) {
            clearInterval(progressTimers[prefix]);
        }
        updateProgress(prefix, 0);
        container.removeClass("hidden");
        bar.addClass("progress-bar-striped active");
        var start = Date.now();
        progressTimers[prefix] = setInterval(function() {
            var elapsed = (Date.now() - start) / 1000;
            var nextValue = Math.min(95, Math.floor(elapsed * 3));
            updateProgress(prefix, nextValue);
        }, 1000);
    }

    function stopProgress(prefix) {
        var container = $("#" + prefix + "_progress");
        var bar = $("#" + prefix + "_progress_bar");
        if (!container.length || !bar.length) {
            return;
        }
        if (progressTimers[prefix]) {
            clearInterval(progressTimers[prefix]);
            progressTimers[prefix] = null;
        }
        updateProgress(prefix, 100);
        bar.removeClass("progress-bar-striped active");
        setTimeout(function() {
            container.addClass("hidden");
        }, 1200);
    }

    function profileLabel(profile) {
        var name = profile.name || "";
        var description = profile.description || "";
        if (description) {
            return name ? name + " - " + description : description;
        }
        return name;
    }

    function renderProfileOptions(list) {
        var scanSelect = $("#scan_profile");
        var hostsSelect = $("#hosts_profile");
        var currentScan = scanSelect.val();
        var currentHosts = hostsSelect.val();
        var options = "";

        list.forEach(function(profile) {
            var label = profileLabel(profile);
            if (!label) {
                label = profile.uuid || "";
            }
            options += "<option value=\"" + escapeHtml(profile.uuid || "") + "\">" + escapeHtml(label) + "</option>";
        });

        if (options === "") {
            options = "<option value=\"\" selected=\"selected\">" +
                "{{ lang._('No profiles available. Add one in Scan Profiles.') }}" +
                "</option>";
        }

        scanSelect.html(options);
        hostsSelect.html(options);

        if (list.length === 0) {
            return;
        }

        function hasUuid(uuid) {
            return list.some(function(item) {
                return item.uuid === uuid;
            });
        }

        var defaultUuid = "";
        list.forEach(function(item) {
            var name = (item.name || "").toLowerCase();
            if (!defaultUuid && (name.indexOf("tcp scan") !== -1 || name.indexOf("regular") !== -1)) {
                defaultUuid = item.uuid;
            }
        });
        if (!defaultUuid && list.length > 0) {
            defaultUuid = list[0].uuid;
        }

        if (currentScan && hasUuid(currentScan)) {
            scanSelect.val(currentScan);
        } else if (defaultUuid) {
            scanSelect.val(defaultUuid);
        }

        if (currentHosts && hasUuid(currentHosts)) {
            hostsSelect.val(currentHosts);
        } else if (defaultUuid) {
            hostsSelect.val(defaultUuid);
        }

    }

    function loadProfiles() {
        ajaxCall("/api/nmap/profiles/search_profile", { "current": 1, "rowCount": -1 }, function(data, status) {
            var rows = data && data.rows ? data.rows : [];
            rows.sort(function(a, b) {
                return (a.name || "").localeCompare(b.name || "");
            });
            renderProfileOptions(rows);
        });
    }

    function formatPorts(ports) {
        if (!ports || ports.length === 0) {
            return "<span class=\"text-muted\">-</span>";
        }
        return ports.map(function(port) {
            var portLabel = escapeHtml(String(port.port)) + "/" + escapeHtml(port.proto || "");
            var service = port.service ? escapeHtml(port.service) : "";
            var detailParts = [];
            if (port.product) {
                detailParts.push(escapeHtml(port.product));
            }
            if (port.version) {
                detailParts.push(escapeHtml(port.version));
            }
            if (port.extra) {
                detailParts.push(escapeHtml(port.extra));
            }
            var details = detailParts.join(" ");
            var line = "<div class=\"nmap-service-line\"><span class=\"label label-info\">" + portLabel + "</span>";
            if (service) {
                line += " " + service;
            }
            if (details) {
                line += " <span class=\"text-muted\">" + details + "</span>";
            }
            if (port.tunnel) {
                line += " <span class=\"text-muted\">[" + escapeHtml(port.tunnel) + "]</span>";
            }
            line += "</div>";
            return line;
        }).join("");
    }

    function renderHosts(data) {
        var hosts = data['hosts'] || [];
        var warnings = data && Array.isArray(data.warnings) ? data.warnings : [];
        var rows = "";
        hosts.forEach(function(host) {
            rows += "<tr>" +
                "<td>" + escapeHtml(host.address || "") + "</td>" +
                "<td>" + escapeHtml(host.hostname || "") + "</td>" +
                "<td>" + escapeHtml(host.mac || "") + "</td>" +
                "<td>" + escapeHtml(host.vendor || "") + "</td>" +
                "<td>" + escapeHtml(host.status || "") + "</td>" +
                "<td>" + formatPorts(host.ports || []) + "</td>" +
                "</tr>";
        });
        $("#hosts_table tbody").html(rows);

        var infoText = "";
        if (data['generated_at']) {
            var dt = new Date(data['generated_at']);
            infoText = "{{ lang._('Last scan') }}: " + dt.toLocaleString();
        }
        if (data['profile']) {
            infoText += " | {{ lang._('Profile') }}: " + data['profile'];
        }
        if (hosts.length === 0) {
            infoText = infoText ? infoText + " | " : "";
            infoText += "{{ lang._('No results recorded yet.') }}";
        } else {
            infoText += " | {{ lang._('Results') }}: " + hosts.length;
        }
        if (warnings.length) {
            infoText = warnings.join(" | ") + (infoText ? " | " + infoText : "");
        }
        if (infoText !== "") {
            $("#hostsInfo").text(infoText).removeClass("hidden");
        }
    }

    function fetchResults(callback) {
        ajaxCall("/api/nmap/service/results", {}, function(data, status) {
            lastResults = data || {};
            callback(lastResults);
        });
    }

    function loadResults() {
        fetchResults(function(data) {
            renderHosts(data);
        });
    }

    function renderInterfaces(list) {
        var rows = "";
        list.forEach(function(item) {
            rows += "<tr>" +
                "<td><input type=\"checkbox\" class=\"nmap-interface\" data-target=\"" + escapeHtml(item.network) + "\" checked=\"checked\" /></td>" +
                "<td>" + escapeHtml(item.name) + "</td>" +
                "<td>" + escapeHtml(item.network) + "</td>" +
                "</tr>";
        });
        $("#interfaces_table tbody").html(rows);
    }

    function loadInterfaces() {
        ajaxCall("/api/nmap/service/interfaces", {}, function(data, status) {
            var list = data['interfaces'] || [];
            renderInterfaces(list);
            $("#hosts_select_all").prop("checked", list.length > 0);
            if (list.length === 0) {
                updateHostsInfo("{{ lang._('No interface networks found. Check interface IP configuration.') }}");
            }
        });
    }

    $("#hosts_select_all").change(function() {
        var checked = $(this).is(":checked");
        $(".nmap-interface").prop("checked", checked);
    });

    $("#scanAct").click(function() {
        var target = $.trim($("#scan_target").val());
        var profile = $("#scan_profile").val();
        if (target === "") {
            updateOutput("#scanOutput", "{{ lang._('Target is required.') }}");
            return;
        }
        if (!profile) {
            updateOutput("#scanOutput", "{{ lang._('Profile is required.') }}");
            return;
        }
        $("#scanAct_progress").addClass("fa fa-spinner fa-pulse");
        startProgress("scan");
        ajaxCall("/api/nmap/service/scan", {
            "target": target,
            "profile": profile
        }, function(data, status) {
            updateOutput("#scanOutput", data['output'] || data['message'] || "");
            $("#scanAct_progress").removeClass("fa fa-spinner fa-pulse");
            stopProgress("scan");
        });
    });

    $("#hostsAct").click(function() {
        var targets = [];
        $(".nmap-interface:checked").each(function() {
            targets.push($(this).data("target"));
        });
        var profile = $("#hosts_profile").val();
        if (targets.length === 0) {
            updateHostsInfo("{{ lang._('Please select at least one interface network.') }}");
            return;
        }
        if (!profile) {
            updateHostsInfo("{{ lang._('Profile is required.') }}");
            return;
        }
        $("#hostsAct_progress").addClass("fa fa-spinner fa-pulse");
        startProgress("hosts");
        ajaxCall("/api/nmap/service/scanhosts", {
            "targets": targets.join(","),
            "profile": profile
        }, function(data, status) {
            $("#hostsAct_progress").removeClass("fa fa-spinner fa-pulse");
            stopProgress("hosts");
            if (data['output']) {
                updateHostsInfo(data['output']);
            } else if (data['message']) {
                updateHostsInfo(data['message']);
            }
            loadResults();
        });
    });

    $("#hostsClear").click(function() {
        ajaxCall("/api/nmap/service/clearresults", {}, function(data, status) {
            if (data && data['cleared']) {
                renderHosts({ "generated_at": null, "hosts": [] });
            }
            if (data && data['message']) {
                updateHostsInfo(data['message']);
            }
        });
    });

    $("#hostsExportJson").click(function() {
        fetchResults(function(data) {
            var filename = buildExportFilename("json", data);
            var payload = JSON.stringify(data || {}, null, 2);
            downloadBlob(payload, filename, "application/json");
        });
    });

    $("#hostsExportCsv").click(function() {
        fetchResults(function(data) {
            var filename = buildExportFilename("csv", data);
            var payload = resultsToCsv(data || {});
            downloadBlob(payload, filename, "text/csv");
        });
    });

    $("#customAct").click(function() {
        var target = $.trim($("#custom_target").val());
        if (target === "") {
            updateOutput("#customOutput", "{{ lang._('Target is required.') }}");
            return;
        }
        $("#customAct_progress").addClass("fa fa-spinner fa-pulse");
        startProgress("custom");
        ajaxCall("/api/nmap/service/scancustom", {
            "target": target,
            "custom_args": $("#custom_args").val()
        }, function(data, status) {
            updateOutput("#customOutput", data['output'] || data['message'] || "");
            $("#customAct_progress").removeClass("fa fa-spinner fa-pulse");
            stopProgress("custom");
        });
    });

    if ($("#{{ profileGrid['table_id'] }}").length) {
        profileGrid = $("#{{ profileGrid['table_id'] }}").UIBootgrid({
            'search': '/api/nmap/profiles/search_profile',
            'get': '/api/nmap/profiles/get_profile/',
            'set': '/api/nmap/profiles/set_profile/',
            'add': '/api/nmap/profiles/add_profile/',
            'del': '/api/nmap/profiles/del_profile/'
        });
        profileGrid.on("loaded.rs.jquery.bootgrid", function() {
            loadProfiles();
        });
    }

    loadInterfaces();
    loadResults();
    loadProfiles();
});
</script>
