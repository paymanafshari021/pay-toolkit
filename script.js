let rowCount = 0;

const tabConfig = {
  sniffer: { title: 'Packet Sniffer', desc: 'Capture and analyze network traffic' },
  flow:    { title: 'Debug Flow', desc: 'Trace packet flow through the system' },
  routing: { title: 'Routing Lookup', desc: 'View routing table and gateway information' },
  ping:    { title: 'Ping Test', desc: 'Test IP connectivity' },
  trace:   { title: 'Traceroute', desc: 'Trace route to destination' },
  ha:      { title: 'HA Troubleshoot', desc: 'Diagnose HA cluster status, sync, and failover' },
  vpn:     { title: 'VPN IKE Debug', desc: 'Debug VPN IKE negotiations' }
};

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => switchTab(item.dataset.tab, item));
});

function switchTab(tabName, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(tabName).classList.add('active');
  el.classList.add('active');
  document.getElementById('pageTitle').textContent = tabConfig[tabName].title;
  document.getElementById('pageDesc').textContent = tabConfig[tabName].desc;
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
        <option value="src host">Src host</option>
        <option value="dst host">Dst host</option>
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
  row.querySelector('.fProtoField').style.display = (type === 'port') ? 'flex' : 'none';
  const valField = row.querySelector('.fVal').parentElement;
  valField.style.display = (['icmp', 'arp'].includes(type)) ? 'none' : 'flex';
}

function removeRow(id) {
  document.getElementById(id).remove();
  genAll();
}

function toggleFlowPort() {
  const proto = document.getElementById('flowProto').value;
  document.getElementById('flowPortField').style.display = (proto === "1") ? "none" : "flex";
}

function clearAllInputs() {
  document.querySelectorAll('input').forEach(input => {
    if (input.id === 'snInt') input.value = 'any';
    else if (input.id === 'snCount') input.value = '0';
    else if (input.id === 'flowTrace') input.value = '10';
    else input.value = '';
  });
  document.querySelectorAll('select').forEach(s => s.selectedIndex = 0);
  document.getElementById('filter-container').innerHTML = '';
  rowCount = 0;
  addFilterRow();
  toggleFlowPort();
  genAll();
}

function genAll() {
  const sInt = document.getElementById('snInt').value || "any";
  const sVerb = document.getElementById('snVerb').value;
  const sCount = document.getElementById('snCount').value || "0";
  const sTS = document.getElementById('snTS').value;

  const rows = document.querySelectorAll('.filter-row');
  let filterParts = [];
  rows.forEach(row => {
    const logic = row.querySelector('.fLogic')?.value || 'and';
    const type = row.querySelector('.fType').value;
    const proto = row.querySelector('.fProto').value;
    const val = row.querySelector('.fVal').value;
    let segment = "";
    if (["icmp", "arp"].includes(type)) segment = type;
    else if (val) segment = (type === "port" && proto) ? `${proto} ${type} ${val}` : `${type} ${val}`;
    if (segment) filterParts.push(filterParts.length === 0 ? segment : `${logic} ${segment}`);
  });
  const fString = filterParts.length > 0 ? ` '${filterParts.join(' ')}'` : "";
  document.getElementById('snOut').innerText = `diag sniffer packet ${sInt}${fString} ${sVerb} ${sCount} ${sTS}`;

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

  const haVcluster = document.getElementById('haVcluster').value || "0";
  const haGroup = document.getElementById('haGroup').value || "0";
  const haUnit = document.getElementById('haUnit').value;
  const haManageCmd = haUnit ? `execute ha manage ${haUnit}\n` : "";

  document.getElementById('haOut').innerText = `get system ha status
get system ha
diagnose sys ha status
diagnose sys ha checksum cluster
diagnose sys ha checksum recalculate
diagnose sys ha showcsum
diagnose sys ha dump-by vcluster ${haVcluster} ${haGroup}
${haManageCmd}diagnose sys ha reset-uptime`;

  const vpnIp = document.getElementById('vpnIp').value || "<destination_ip>";
  document.getElementById('vpnOut').innerText = `diagnose debug disable
diagnose vpn ike log filter clear
diagnose vpn ike log filter rem-addr4 ${vpnIp}
diagnose debug application ike -1
diagnose debug enable`;

  const rtIp = document.getElementById('rtIp').value || "<destination_ip>";
  document.getElementById('rtOut').innerText = `get router info routing-table details ${rtIp}`;

  document.getElementById('pOut').innerText = `execute ping-options source ${document.getElementById('pSrc').value || '<source_ip>'}
execute ping ${document.getElementById('pDst').value || '<destination_ip>'}`;

  document.getElementById('tOut').innerText = `execute traceroute-options source ${document.getElementById('tSrc').value || '<source_ip>'}
execute traceroute ${document.getElementById('tDst').value || '<destination_ip>'}`;
}

function copy(el) {
  if (!el.innerText.trim()) return;
  navigator.clipboard.writeText(el.innerText);
  el.classList.add('copied');
  setTimeout(() => el.classList.remove('copied'), 900);
}

addFilterRow();
genAll();
