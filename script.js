let rowCount = 0;

// THEME TOGGLE FUNCTIONALITY
function toggleTheme() {
    const body = document.body;
    const themeIcon = document.getElementById('themeIcon');
    
    if (body.classList.contains('light-theme')) {
        // Switch to dark theme
        body.classList.remove('light-theme');
        themeIcon.textContent = '🌙';
        localStorage.setItem('theme', 'dark');
    } else {
        // Switch to light theme
        body.classList.add('light-theme');
        themeIcon.textContent = '☀️';
        localStorage.setItem('theme', 'light');
    }
}

// Detect system preference and initialize theme
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const themeIcon = document.getElementById('themeIcon');
    
    if (savedTheme) {
        // Use saved preference
        if (savedTheme === 'light') {
            document.body.classList.add('light-theme');
            themeIcon.textContent = '☀️';
        } else {
            document.body.classList.remove('light-theme');
            themeIcon.textContent = '🌙';
        }
    } else if (!prefersDark) {
        // Auto-switch to light theme if system prefers light
        document.body.classList.add('light-theme');
        themeIcon.textContent = '☀️';
        localStorage.setItem('theme', 'light');
    } else {
        // Keep dark theme (default)
        document.body.classList.remove('light-theme');
        themeIcon.textContent = '🌙';
        localStorage.setItem('theme', 'dark');
    }
}

// Listen for system theme changes
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    if (!localStorage.getItem('theme')) {
        if (e.matches) {
            document.body.classList.remove('light-theme');
            document.getElementById('themeIcon').textContent = '🌙';
        } else {
            document.body.classList.add('light-theme');
            document.getElementById('themeIcon').textContent = '☀️';
        }
    }
});

const tabConfig = {
    sniffer: { icon: '📡', title: 'Packet Sniffer', desc: 'Capture and analyze network traffic' },
    flow: { icon: '🔍', title: 'Debug Flow', desc: 'Trace packet flow through the system' },
    routing: { icon: '🛣️', title: 'Routing Lookup', desc: 'View routing table and gateway information' },
    ping: { icon: '📍', title: 'Ping Test', desc: 'Test IP connectivity' },
    trace: { icon: '📍📍', title: 'Traceroute', desc: 'Trace route to destination' },
    vpn: { icon: '🔐', title: 'VPN IKE Debug', desc: 'Debug VPN IKE negotiations' }
};

function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from all nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(tabName).classList.add('active');

    // Add active class to clicked nav item
    event.target.closest('.nav-item').classList.add('active');

    // Update top bar
    const config = tabConfig[tabName];
    document.getElementById('pageIcon').textContent = config.icon;
    document.getElementById('pageTitle').textContent = config.title;
    document.getElementById('pageDesc').textContent = config.desc;

    // Generate output
    genAll();
}

function addFilterRow() {
    rowCount++;
    const container = document.getElementById('filter-container');
    const row = document.createElement('div');
    row.className = 'filter-row';
    row.id = `row-${rowCount}`;

    row.innerHTML = `
        <div class="filter-logic">
            <select class="fLogic" onchange="genAll()">
                <option value="and">AND</option>
                <option value="or">OR</option>
            </select>
        </div>
        <div class="field">
            <label>Type</label>
            <select class="fType" onchange="toggleRowFields('${row.id}'); genAll();">
                <option value="host">Host IP</option>
                <option value="net">Network (CIDR)</option>
                <option value="port" selected>Port</option>
                <option value="src host">Src Host</option>
                <option value="dst host">Dst Host</option>
                <option value="icmp">ICMP</option>
                <option value="arp">ARP</option>
            </select>
        </div>
        <div class="field fProtoField">
            <label>Protocol</label>
            <select class="fProto" onchange="genAll()">
                <option value="">any</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
            </select>
        </div>
        <div class="field">
            <label>Value</label>
            <input type="text" class="fVal" placeholder="e.g., 192.168.1.0/24" oninput="genAll()">
        </div>
        <button class="remove-btn" onclick="removeRow('${row.id}')">×</button>
    `;

    container.appendChild(row);
    toggleRowFields(row.id);
    genAll();
}

function toggleRowFields(rowId) {
    const row = document.getElementById(rowId);
    const type = row.querySelector('.fType').value;
    const protoField = row.querySelector('.fProtoField');
    const valInput = row.querySelector('.fVal');

    protoField.style.display = (type === 'port') ? 'flex' : 'none';
    valInput.parentElement.style.display = (['icmp', 'arp'].includes(type)) ? 'none' : 'flex';
}

function removeRow(id) {
    document.getElementById(id).remove();
    genAll();
}

function toggleFlowPort() {
    const proto = document.getElementById('flowProto').value;
    const portField = document.getElementById('flowPortField');
    portField.style.display = (proto === "1") ? "none" : "flex";
}

function clearAllInputs() {
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        if (input.id === 'snInt') input.value = 'any';
        else if (input.id === 'snCount') input.value = '0';
        else if (input.id === 'flowTrace') input.value = '10';
        else input.value = '';
    });

    const selects = document.querySelectorAll('select');
    selects.forEach(select => select.selectedIndex = 0);

    document.getElementById('filter-container').innerHTML = '';
    rowCount = 0;
    addFilterRow();
    toggleFlowPort();
    genAll();
}

function genAll() {
    // Sniffer
    const sInt = document.getElementById('snInt').value || "any";
    const sVerb = document.getElementById('snVerb').value;
    const sCount = document.getElementById('snCount').value || "0";
    const sTS = document.getElementById('snTS').value;

    const rows = document.querySelectorAll('.filter-row');
    let filterParts = [];

    rows.forEach((row) => {
        const logic = row.querySelector('.fLogic')?.value || 'and';
        const type = row.querySelector('.fType').value;
        const proto = row.querySelector('.fProto').value;
        const val = row.querySelector('.fVal').value;

        let segment = "";
        if (["icmp", "arp"].includes(type)) {
            segment = type;
        } else if (val) {
            if (type === "port" && proto) {
                segment = `${proto} ${type} ${val}`;
            } else {
                segment = `${type} ${val}`;
            }
        }

        if (segment) {
            if (filterParts.length === 0) filterParts.push(segment);
            else filterParts.push(`${logic} ${segment}`);
        }
    });

    const fString = filterParts.length > 0 ? ` '${filterParts.join(' ')}'` : "";
    document.getElementById('snOut').innerText = `diag sniffer packet ${sInt}${fString} ${sVerb} ${sCount} ${sTS}`;

    // Flow
    const fAddr = document.getElementById('flowAddr').value || "<ip_address>";
    const fProto = document.getElementById('flowProto').value;
    const fPort = document.getElementById('flowPort').value || "<port>";
    const fCount = document.getElementById('flowTrace').value || "10";
    const portCmd = (fProto === "1") ? "" : `diag debug flow filter port ${fPort}\n`;

    document.getElementById('flowOut').innerText = `diag debug disable
diag debug flow trace stop
diag debug flow filter clear
diag debug reset

diag debug flow filter addr ${fAddr}
diag debug flow filter proto ${fProto}
${portCmd}diag debug flow show function-name enable
diag debug flow show iprope enable
diag debug console timestamp enable
diag debug flow trace start ${fCount}

diag debug enable`;

    // VPN
    const vpnIp = document.getElementById('vpnIp').value || "<destination_ip>";
    document.getElementById('vpnOut').innerText = `diagnose debug disable
diagnose vpn ike log filter clear
diagnose vpn ike log filter rem-addr4 ${vpnIp}
diagnose debug application ike -1
diagnose debug enable`;

    // Routing
    const rtIp = document.getElementById('rtIp').value || "<destination_ip>";
    document.getElementById('rtOut').innerText = `get router info routing-table details ${rtIp}`;

    // Ping & Traceroute
    document.getElementById('pOut').innerText = `execute ping-options source ${document.getElementById('pSrc').value || '<source_ip>'}
execute ping ${document.getElementById('pDst').value || '<destination_ip>'}`;

    document.getElementById('tOut').innerText = `execute traceroute-options source ${document.getElementById('tSrc').value || '<source_ip>'}
execute traceroute ${document.getElementById('tDst').value || '<destination_ip>'}`;
}

function copy(el) {
    if (!el.innerText || el.innerText.trim() === "") return;

    navigator.clipboard.writeText(el.innerText);
    el.classList.remove('copied');
    void el.offsetWidth;
    el.classList.add('copied');

    setTimeout(() => {
        el.classList.remove('copied');
    }, 600);
}

// Initialize
initializeTheme();
addFilterRow();
genAll();