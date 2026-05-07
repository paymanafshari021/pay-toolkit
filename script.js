let rowCount = 0;

/**
 * Add a new filter row to the sniffer card with smooth animation
 */
function addFilterRow() {
    rowCount++;
    const container = document.getElementById('filter-container');
    const row = document.createElement('div');
    row.className = 'input-group filter-row';
    row.id = `row-${rowCount}`;
    row.style.animation = 'slideInRow 0.4s cubic-bezier(0.34, 1.56, 0.64, 1)';
    
    row.innerHTML = `
        <div class="field" style="flex: 0 0 70px; ${rowCount === 1 ? 'display:none' : ''}">
            <label>Logic</label>
            <select class="fLogic" onchange="genAll()">
                <option value="and">AND</option>
                <option value="or">OR</option>
            </select>
        </div>

        <div class="field" style="flex: 1">
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

        <div class="field fProtoField" style="flex: 1; display: flex;">
            <label>Protocol</label>
            <select class="fProto" onchange="genAll()">
                <option value="">any</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
            </select>
        </div>

        <div class="field" style="flex: 2">
            <label>Value</label>
            <input type="text" class="fVal" placeholder="Value..." oninput="genAll()">
        </div>

        <button class="remove-btn" onclick="removeRow('${row.id}')" title="Remove filter">×</button>
    `;
    
    container.appendChild(row);
    toggleRowFields(row.id);
    genAll();
}

/**
 * Animation for row insertion
 */
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRow {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
`;
document.head.appendChild(style);

/**
 * Toggle visibility of protocol field and value input based on filter type
 * @param {string} rowId - The ID of the filter row
 */
function toggleRowFields(rowId) {
    const row = document.getElementById(rowId);
    const type = row.querySelector('.fType').value;
    const protoField = row.querySelector('.fProtoField');
    const valInput = row.querySelector('.fVal');
    
    protoField.style.display = (type === 'port') ? 'flex' : 'none';
    valInput.parentElement.style.display = (['icmp', 'arp'].includes(type)) ? 'none' : 'flex';
}

/**
 * Remove a filter row with smooth animation
 * @param {string} id - The ID of the row to remove
 */
function removeRow(id) {
    const element = document.getElementById(id);
    element.style.animation = 'slideOutRow 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) forwards';
    setTimeout(() => {
        element.remove();
        genAll();
    }, 400);
}

const slideOutStyle = document.createElement('style');
slideOutStyle.textContent = `
    @keyframes slideOutRow {
        to {
            opacity: 0;
            transform: translateX(20px);
        }
    }
`;
document.head.appendChild(slideOutStyle);

/**
 * Toggle port field visibility based on protocol selection in Debug Flow
 */
function toggleFlowPort() {
    const proto = document.getElementById('flowProto').value;
    const portField = document.getElementById('flowPortField');
    portField.style.display = (proto === "1") ? "none" : "flex";
}

/**
 * Clear all input fields and reset to defaults with confirmation
 */
function clearAllInputs() {
    if (!confirm('Clear all inputs? This action cannot be undone.')) return;
    
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

/**
 * Generate all command outputs based on current input values
 */
function genAll() {
    genSniffer();
    genFlow();
    genVPN();
    genRouting();
    genTools();
}

/**
 * Generate Dynamic Packet Sniffer command
 */
function genSniffer() {
    const sInt = document.getElementById('snInt').value || "any";
    const sVerb = document.getElementById('snVerb').value;
    const sCount = document.getElementById('snCount').value || "0";
    const sTS = document.getElementById('snTS').value;
    const rows = document.querySelectorAll('.filter-row');
    
    let filterParts = [];
    rows.forEach((row) => {
        const logic = row.querySelector('.fLogic').value;
        const type = row.querySelector('.fType').value;
        const proto = row.querySelector('.fProto').value;
        const val = row.querySelector('.fVal').value;
        
        let segment = "";
        if (["icmp", "arp"].includes(type)) {
            segment = type;
        } else if (val) {
            if (type === "port" && proto !== "") {
                segment = `${proto} ${type} ${val}`;
            } else {
                segment = `${type} ${val}`;
            }
        }
        
        if (segment) {
            if (filterParts.length === 0) {
                filterParts.push(segment);
            } else {
                filterParts.push(`${logic} ${segment}`);
            }
        }
    });
    
    let fString = filterParts.length > 0 ? ` '${filterParts.join(' ')}'` : "";
    document.getElementById('snOut').innerText = `diag sniffer packet ${sInt}${fString} ${sVerb} ${sCount} ${sTS}`;
}

/**
 * Generate Debug Flow (Packet Tracing) command
 */
function genFlow() {
    const fAddr = document.getElementById('flowAddr').value || "<ip_address>";
    const fProto = document.getElementById('flowProto').value;
    const fPort = document.getElementById('flowPort').value || "<port>";
    const fCount = document.getElementById('flowTrace').value || "10";
    
    let portCmd = (fProto === "1") ? "" : `diag debug flow filter port ${fPort}\n`;
    
    const command = `diag debug disable
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
    
    document.getElementById('flowOut').innerText = command;
}

/**
 * Generate VPN IKE Debug command
 */
function genVPN() {
    const vpnIp = document.getElementById('vpnIp').value || "<destination_ip>";
    const command = `diagnose debug disable
diagnose vpn ike log filter clear
diagnose vpn ike log filter rem-addr4 ${vpnIp}
diagnose debug application ike -1
diagnose debug enable`;
    
    document.getElementById('vpnOut').innerText = command;
}

/**
 * Generate Routing & Gateway Lookup command
 */
function genRouting() {
    const rtIp = document.getElementById('rtIp').value || "<destination_ip>";
    document.getElementById('rtOut').innerText = `get router info routing-table details ${rtIp}`;
}

/**
 * Generate Ping and Traceroute commands
 */
function genTools() {
    const pSrc = document.getElementById('pSrc').value || '<source_ip>';
    const pDst = document.getElementById('pDst').value || '<destination_ip>';
    const tSrc = document.getElementById('tSrc').value || '<source_ip>';
    const tDst = document.getElementById('tDst').value || '<destination_ip>';
    
    document.getElementById('pOut').innerText = `execute ping-options source ${pSrc}\nexecute ping ${pDst}`;
    document.getElementById('tOut').innerText = `execute traceroute-options source ${tSrc}\nexecute traceroute ${tDst}`;
}

/**
 * Copy code block text to clipboard with visual feedback
 * @param {HTMLElement} el - The code block element to copy from
 */
function copy(el) {
    if (!el.innerText || el.innerText.trim() === "") return;
    
    navigator.clipboard.writeText(el.innerText).then(() => {
        el.classList.remove('copy-flash');
        void el.offsetWidth; // Trigger reflow
        el.classList.add('copy-flash');
        
        // Visual feedback - change text temporarily
        const originalText = el.textContent;
        el.textContent = '✓ COPIED';
        el.style.opacity = '0.8';
        
        setTimeout(() => {
            el.textContent = originalText;
            el.style.opacity = '1';
        }, 1200);
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy to clipboard');
    });
}

/**
 * Initialize the page by adding the first filter row
 */
document.addEventListener('DOMContentLoaded', function() {
    addFilterRow();
    
    // Add smooth scroll behavior to all inputs
    document.querySelectorAll('input, select').forEach(el => {
        el.addEventListener('focus', function() {
            this.scrollIntoView({ behavior: 'smooth', block: 'center' });
        });
    });
});

/**
 * Add keyboard shortcuts
 */
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K to clear all
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        clearAllInputs();
    }
    // Ctrl/Cmd + L to add filter row
    if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        addFilterRow();
    }
});