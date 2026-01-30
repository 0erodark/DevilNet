// --- Captive Portal Logic ---
async function toggleCaptivePortal(ip) {
    const btnId = `btn-captive-${ipToLong(ip)}`;
    const btn = document.getElementById(btnId);

    // Toggle state styling tentatively
    const icon = btn.querySelector('i');
    const isActive = icon.classList.contains('text-red-500'); // Assuming red means active/locked

    const newState = !isActive;

    try {
        const response = await fetch('/api/settings/captive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, enable: newState })
        });

        if (response.ok) {
            // Update UI
            if (newState) {
                icon.classList.remove('ri-door-lock-line');
                icon.classList.add('ri-door-lock-fill', 'text-red-500');
                btn.classList.add('bg-red-500/10');
            } else {
                icon.classList.remove('ri-door-lock-fill', 'text-red-500');
                icon.classList.add('ri-door-lock-line');
                btn.classList.remove('bg-red-500/10');
            }
        } else {
            console.error("Failed to toggle captive portal");
        }
    } catch (e) {
        console.error(e);
    }
}
