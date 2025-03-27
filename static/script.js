document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('file-input');
    const fileNameDisplay = document.getElementById('file-name');
    const filePreview = document.getElementById('file-preview');
    const keyIdDisplay = document.getElementById('key-id-display');
    const generateKeyBtn = document.getElementById('generate-key-btn');
    const signBtn = document.getElementById('sign-btn');
    const verifyBtn = document.getElementById('verify-btn');
    const logOutput = document.getElementById('log-output');
    const themeToggleBtn = document.getElementById('theme-toggle-btn');

    // Modal elements
    const modal = document.getElementById('key-gen-modal');
    const modalContent = modal.querySelector('.modal-content');
    const modalAlgorithm = document.getElementById('modal-algorithm');
    const modalKeyId = document.getElementById('modal-key-id');
    const modalGenerateBtn = document.getElementById('modal-generate-btn');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const closeModal = document.getElementById('close-modal');

    let selectedFile = null;
    let currentKeyId = null;

    // Initialize Particles.js with adjusted opacity for nodes and edges
    particlesJS('particles-js', {
        particles: {
            number: { value: 80, density: { enable: true, value_area: 800 } },
            color: { value: '#e6e6fa' }, // White color for nodes
            shape: { type: 'circle' },
            opacity: { 
                value: 0.85, // Decreased from 0.9 to 0.85
                random: true 
            },
            size: { value: 3, random: true },
            line_linked: { 
                enable: true, 
                distance: 150, 
                color: '#e6e6fa', // White color for edges
                opacity: 0.65, // Decreased from 0.7 to 0.65
                width: 1 
            },
            move: { enable: true, speed: 2, direction: 'none', random: false, straight: false, out_mode: 'out', bounce: false }
        },
        interactivity: {
            detect_on: 'canvas',
            events: { onhover: { enable: true, mode: 'repulse' }, onclick: { enable: true, mode: 'push' }, resize: true },
            modes: { repulse: { distance: 100, duration: 0.4 }, push: { particles_nb: 4 } }
        },
        retina_detect: true
    });

    // Theme Toggle
    themeToggleBtn.addEventListener('click', () => {
        document.body.classList.toggle('dark-theme');
        document.body.classList.toggle('light-theme');
        themeToggleBtn.innerHTML = document.body.classList.contains('dark-theme') ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
        playSound('click');

        // Update particle colors based on theme
        const particleColor = document.body.classList.contains('dark-theme') ? '#e6e6fa' : '#4b0082';
        particlesJS('particles-js', {
            particles: {
                number: { value: 80, density: { enable: true, value_area: 800 } },
                color: { value: particleColor },
                shape: { type: 'circle' },
                opacity: { value: 0.85, random: true }, // Updated opacity
                size: { value: 3, random: true },
                line_linked: { enable: true, distance: 150, color: particleColor, opacity: 0.65, width: 1 }, // Updated opacity
                move: { enable: true, speed: 2, direction: 'none', random: false, straight: false, out_mode: 'out', bounce: false }
            },
            interactivity: {
                detect_on: 'canvas',
                events: { onhover: { enable: true, mode: 'repulse' }, onclick: { enable: true, mode: 'push' }, resize: true },
                modes: { repulse: { distance: 100, duration: 0.4 }, push: { particles_nb: 4 } }
            },
            retina_detect: true
        });
    });

    // Sound Effects
    const playSound = (type) => {
        const audio = new Audio();
        if (type === 'click') {
            audio.src = 'data:audio/mpeg;base64,/+MYxAAAAANIAAAAAExBTUUzLjk4LjIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
            audio.volume = 0.3;
        } else if (type === 'select') {
            audio.src = 'data:audio/mpeg;base64,/+MYxAAAAANIAAAAAExBTUUzLjk4LjIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
            audio.volume = 0.5;
        }
        audio.play().catch(() => {});
    };

    // Log function with animation
    const log = (message, type = 'info') => {
        const timestamp = new Date().toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'medium' });
        const logEntry = document.createElement('div');
        logEntry.textContent = `[${timestamp}] ${message}`;
        logEntry.className = `log-entry ${type}`;
        logOutput.appendChild(logEntry);
        logOutput.scrollTop = logOutput.scrollHeight;
        setTimeout(() => {
            logEntry.classList.add('show');
        }, 10);
    };

    // Show/hide spinner
    const toggleSpinner = (button, show) => {
        const spinner = button.querySelector('.spinner');
        const text = button.querySelector('.btn-text');
        if (show) {
            spinner.classList.remove('hidden');
            text.style.opacity = '0.5';
        } else {
            spinner.classList.add('hidden');
            text.style.opacity = '1';
        }
    };

    // Enable/disable buttons
    const updateButtons = () => {
        signBtn.disabled = !selectedFile || !currentKeyId;
        verifyBtn.disabled = !selectedFile;
    };

    // Show/hide modal with animation
    const showModal = () => {
        modal.style.display = 'flex';
        setTimeout(() => {
            modalContent.classList.add('show');
        }, 10);
    };

    const hideModal = () => {
        modalContent.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            modalKeyId.value = ''; // Reset Key ID input
        }, 300);
    };

    // File selection
    fileInput.addEventListener('change', (e) => {
        selectedFile = e.target.files[0];
        if (selectedFile) {
            fileNameDisplay.textContent = selectedFile.name;
            filePreview.textContent = `Type: ${selectedFile.type || 'Unknown'}, Size: ${(selectedFile.size / 1024).toFixed(2)} KB`;
            filePreview.classList.add('show');
            log(`Selected file: ${selectedFile.name}`, 'success');
            playSound('select');
        } else {
            fileNameDisplay.textContent = 'No file selected';
            filePreview.textContent = '';
            filePreview.classList.remove('show');
            log('No file selected', 'error');
        }
        updateButtons();
    });

    // Open modal on "Generate Key" click
    generateKeyBtn.addEventListener('click', () => {
        showModal();
        playSound('click');
    });

    // Close modal
    closeModal.addEventListener('click', () => {
        hideModal();
        playSound('click');
    });
    modalCancelBtn.addEventListener('click', () => {
        hideModal();
        playSound('click');
    });

    // Generate key from modal
    modalGenerateBtn.addEventListener('click', async () => {
        modalGenerateBtn.disabled = true;
        toggleSpinner(modalGenerateBtn, true);
        try {
            const algorithm = modalAlgorithm.value;
            const response = await fetch('/api/generate-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ algorithm })
            });
            const data = await response.json();
            if (data.keyId) {
                currentKeyId = data.keyId;
                keyIdDisplay.value = currentKeyId; // Display Key ID
                log(`Generated ${algorithm} key pair. Key ID: ${currentKeyId}`, 'success');
                updateButtons();
                hideModal();
                playSound('click');
            } else {
                throw new Error(data.error || 'Key generation failed');
            }
        } catch (error) {
            log(`Key generation failed: ${error.message}`, 'error');
        } finally {
            modalGenerateBtn.disabled = false;
            toggleSpinner(modalGenerateBtn, false);
        }
    });

    // Sign file
    signBtn.addEventListener('click', async () => {
        if (!selectedFile || !currentKeyId) return;
        signBtn.disabled = true;
        toggleSpinner(signBtn, true);
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('keyId', currentKeyId);

        try {
            const response = await fetch('/api/sign-file', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            if (data.success) {
                log(`File signed successfully`, 'success');
                playSound('click');
            } else {
                throw new Error(data.error || 'Signing failed');
            }
        } catch (error) {
            log(`Signing failed: ${error.message}`, 'error');
        } finally {
            signBtn.disabled = false;
            toggleSpinner(signBtn, false);
        }
    });

    // Verify signature
    verifyBtn.addEventListener('click', async () => {
        if (!selectedFile) return;
        verifyBtn.disabled = true;
        toggleSpinner(verifyBtn, true);
        const formData = new FormData();
        formData.append('file', selectedFile);

        try {
            const response = await fetch('/api/verify-signature', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            if (data.isValid !== undefined) {
                log(`Signature verification: ${data.isValid ? 'Valid' : 'Invalid'}`, data.isValid ? 'success' : 'error');
                playSound('click');
            } else {
                throw new Error(data.error || 'Verification failed');
            }
        } catch (error) {
            log(`Verification failed: ${error.message}`, 'error');
        } finally {
            verifyBtn.disabled = false;
            toggleSpinner(verifyBtn, false);
        }
    });

    // Keyboard Accessibility
    document.querySelectorAll('button, input, select').forEach(element => {
        element.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !element.disabled) {
                element.click();
            }
        });
    });
});