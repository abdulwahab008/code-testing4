document.addEventListener('DOMContentLoaded', () => {
    const codeForm = document.getElementById('codeForm');
    const codeInput = document.getElementById('codeInput');
    const resultDiv = document.getElementById('result');
    const accountBtn = document.getElementById('accountBtn');
    const accountDropdown = document.querySelector('.account-dropdown');

    if (codeForm) {
        codeForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = codeInput.value;

            try {
                const response = await fetch('/api/check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ code })
                });

                if (!response.ok) {
                    const text = await response.text();
                    console.error('Response not OK:', text);
                    throw new Error(`HTTP error! status: ${response.status} - ${text}`);
                }

                const result = await response.json();
                displayResults(result);
            } catch (error) {
                console.error('Error:', error);
                resultDiv.innerHTML = `<p class="error">An error occurred: ${error.message}</p>`;
            }
        });
    }

    function displayResults(result) {
        resultDiv.innerHTML = '<h2>Vulnerability Analysis:</h2>';

        const vulnerabilityCategories = ['XSS', 'CodeInjection', 'SQLInjection'];

        vulnerabilityCategories.forEach(category => {
            const categoryData = result[category] || { vulnerable: '0.0', issues: [] };
            const percentage = parseFloat(categoryData.vulnerable || '0.0');

            resultDiv.innerHTML += `
                <div class="vulnerability-category">
                    <h3>${category} (${percentage.toFixed(1)}%):</h3>
                    <div class="chart-container">
                        <div class="chart" style="width: ${percentage}%;"></div>
                    </div>
                    <ul class="vulnerability-list">
                        ${categoryData.issues.length > 0 
                            ? categoryData.issues.map(vuln => `<li>${vuln}</li>`).join('') 
                            : '<li>No vulnerabilities detected</li>'}
                    </ul>
                </div>`;
        });

        renderCharts(result);
    }

    function renderCharts(result) {
        const xssVulnerable = parseFloat(result.XSS?.vulnerable || '0.0');
        const codeInjectionVulnerable = parseFloat(result.CodeInjection?.vulnerable || '0.0');
        const sqlInjectionVulnerable = parseFloat(result.SQLInjection?.vulnerable || '0.0');

        const xssChart = new Chart(document.getElementById('xssChart'), {
            type: 'bar',
            data: {
                labels: ['XSS'],
                datasets: [{
                    label: 'XSS Vulnerabilities',
                    data: [xssVulnerable],
                    backgroundColor: 'rgba(231, 76, 60, 0.2)',
                    borderColor: 'rgba(231, 76, 60, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });

        const codeInjectionChart = new Chart(document.getElementById('codeInjectionChart'), {
            type: 'bar',
            data: {
                labels: ['Code Injection'],
                datasets: [{
                    label: 'Code Injection Vulnerabilities',
                    data: [codeInjectionVulnerable],
                    backgroundColor: 'rgba(52, 152, 219, 0.2)',
                    borderColor: 'rgba(52, 152, 219, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });

        const sqlInjectionChart = new Chart(document.getElementById('sqlInjectionChart'), {
            type: 'bar',
            data: {
                labels: ['SQL Injection'],
                datasets: [{
                    label: 'SQL Injection Vulnerabilities',
                    data: [sqlInjectionVulnerable],
                    backgroundColor: 'rgba(155, 89, 182, 0.2)',
                    borderColor: 'rgba(155, 89, 182, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }

    if (accountBtn) {
        accountBtn.addEventListener('click', () => {
            accountDropdown.style.display = accountDropdown.style.display === 'block' ? 'none' : 'block';
        });

        window.addEventListener('click', (event) => {
            if (!event.target.matches('#accountBtn')) {
                accountDropdown.style.display = 'none';
            }
        });
    }
});
