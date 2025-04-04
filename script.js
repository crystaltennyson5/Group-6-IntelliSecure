document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('booking-form');
    const confirmationMessage = document.getElementById('confirmation-message');

    form.addEventListener('submit', (e) => {
        e.preventDefault();

        const name = document.getElementById('name').value;
        const email = document.getElementById('email').value;
        const service = document.getElementById('service').value;
        const date = document.getElementById('date').value;

        // Basic form validation
        if (!name || !email || !service || !date) {
            alert('Please fill in all the fields!');
            return;
        }

        // Display confirmation message
        confirmationMessage.innerHTML = `<p>Thank you, ${name}! Your ${service} appointment is confirmed for ${date}. We will send a confirmation email to ${email}.</p>`;
        
        // Clear form
        form.reset();
    });
});
