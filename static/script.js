let myChart = null; // Store chart instance

async function startScan() {
    const url = document.getElementById('urlInput').value;
    const loader = document.getElementById('loader');
    const results = document.getElementById('results');
    const errorMsg = document.getElementById('errorMsg');
    
    if(!url) return alert("Enter a URL!");

    results.classList.add('hidden');
    loader.classList.remove('hidden');
    errorMsg.innerText = "";

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url})
        });
        const data = await response.json();

        if(data.error) {
            errorMsg.innerText = data.error;
        } else {
            updateUI(data);
            loader.classList.add('hidden');
            results.classList.remove('hidden');
        }
    } catch(e) {
        errorMsg.innerText = "Connection Failed.";
        loader.classList.add('hidden');
    }
}

function updateUI(data) {
    // 1. Grade
    const circle = document.getElementById('gradeCircle');
    circle.className = `grade-circle grade-${data.grade}`;
    circle.innerText = data.grade;
    document.getElementById('riskText').innerText = `Risk Score: ${data.risk_score}/100`;

    // 2. Server Intel
    document.getElementById('ipText').innerText = data.server_info.ip;
    document.getElementById('locText').innerText = data.server_info.location;
    document.getElementById('latText').innerText = data.server_info.latency;
    
    // SSL Text Color Logic
    const sslText = document.getElementById('sslText');
    const sslVal = data.server_info.ssl_expiry || "N/A";
    sslText.innerText = sslVal;
    
    if(sslVal === "Invalid" || (parseInt(sslVal) < 0)) {
        sslText.style.color = "#ef4444"; // Red
    } else if (parseInt(sslVal) < 30) {
        sslText.style.color = "#f97316"; // Orange
    } else {
        sslText.style.color = "#10b981"; // Green
    }

    // 3. Render Chart
    renderChart(data.stats);

    // 4. Vulnerabilities
    const vulnList = document.getElementById('vulnList');
    vulnList.innerHTML = "";
    if(data.vulnerabilities.length === 0) {
        vulnList.innerHTML = "<p class='safe-text'>No vulnerabilities found.</p>";
    } else {
        data.vulnerabilities.forEach(v => {
            vulnList.innerHTML += `
                <div class="vuln-item">
                    <div class="v-head">
                        <strong>${v.title}</strong>
                        <span class="badge ${v.severity}">${v.severity}</span>
                    </div>
                    <p>${v.layman}</p>
                    <code class="fix">${v.tech_fix}</code>
                </div>`;
        });
    }

    // 5. Good List
    const goodList = document.getElementById('goodList');
    goodList.innerHTML = "";
    data.good_practices.forEach(g => {
        goodList.innerHTML += `<div class="good-item"><i class="fas fa-check"></i> ${g}</div>`;
    });
}

function renderChart(stats) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    
    // Destroy old chart if exists
    if(myChart) myChart.destroy();

    myChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Medium', 'Low', 'Safe'],
            datasets: [{
                data: [stats.high, stats.medium, stats.low, stats.safe],
                backgroundColor: ['#ef4444', '#f97316', '#3b82f6', '#10b981'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right' }
            }
        }
    });
}