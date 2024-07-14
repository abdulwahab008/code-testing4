const accountBtn = document.getElementById('accountBtn');
const accountDropdown = document.querySelector('.account-dropdown');

document.addEventListener("DOMContentLoaded", () => {
    const ctx1 = document.getElementById('xssChart').getContext('2d');
    new Chart(ctx1, {
        type: 'bar',
        data: {
            labels: ['Persistent', 'Reflected', 'DOM-based'],
            datasets: [{
                label: 'XSS Vulnerabilities',
                data: [12, 19, 3],
                backgroundColor: ['#e74c3c', '#3498db', '#2ecc71']
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    const ctx2 = document.getElementById('codeInjectionChart').getContext('2d');
    new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: ['Eval Injection', 'Function Constructor Injection'],
            datasets: [{
                label: 'Code Injection Vulnerabilities',
                data: [7, 4],
                backgroundColor: ['#9b59b6', '#34495e']
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
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
