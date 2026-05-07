let rowCount = 0;

// Tab Switching
document.querySelectorAll('.menu li').forEach(item => {
    item.addEventListener('click', () => {
        document.querySelectorAll('.menu li').forEach(li => li.classList.remove('active'));
        item.classList.add('active');

        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
        document.getElementById(item.dataset.tab).classList.add('active');

        genAll();
    });
});

function addFilterRow() {
    rowCount++;
    const container = document.getElementById('filter-container');
    const row = document.createElement('div');
    row.className = 'input-group filter-row';
    row.id = `row-${rowCount}`;

    row.innerHTML = `
        <div class="field" style="flex: 0 0 70px; ${rowCount === 1 ? 'display:none' : ''}">
            <label>Logic</label>
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
            <input type="text" class="fVal" placeholder="Value..." oninput="genAll()">
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
    const valField = row.querySelector('.fVal').parentElement;

    protoField.style.display = (type === 'port') ? 'block' : 'none';
    valField.style.display = (['icmp', 'arp'].includes(type)) ? 'none' : 'block';
}

function removeRow(id) {
    document.getElementById(id).remove();
    genAll();
}

function toggleFlowPort() {
    const proto = document.getElementById('flowProto').value;
    document.getElementById('flowPortField').style.display = (proto === "1") ? "none" : "block";
}

function clearAllInputs() {
    document.querySelectorAll('input').forEach(input => {
        if (input.id === 'snInt') input.value = 'any';
        else if (input.id === 'snCount') input.value = '0';
        else if (input.id === 'flowTrace') input.value = '10';
        else input.value = '';
    });

    document.getElementById('filter-container').innerHTML = '';
    rowCount = 0;
    addFilterRow();
    genAll();
}

function genAll() {
    // ... (Same logic as before - I'll keep it short here)
    // You can copy the full genAll() function from my previous response
    // Just update the IDs accordingly.
}

// Copy function
function copy(el) {
    if (!el.innerText.trim()) return;
    navigator.clipboard.writeText(el.innerText);
    el.style.transition = 'all 0.3s';
    el.style.background = '#14532d';
    setTimeout(() => el.style.background = '#0a1422', 600);
}

// Initialize
addFilterRow();