// SecureMail AI Client Scripts

document.addEventListener('DOMContentLoaded', () => {
    // 1. Theme Management (Dark/Light mode)
    const themeToggleBtn = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    
    // Get stored theme or default to dark
    const currentTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    updateThemeIcon(currentTheme);
    
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            const targetTheme = current === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', targetTheme);
            localStorage.setItem('theme', targetTheme);
            updateThemeIcon(targetTheme);
        });
    }
    
    function updateThemeIcon(theme) {
        if (!themeIcon) return;
        if (theme === 'light') {
            themeIcon.classList.remove('fa-sun');
            themeIcon.classList.add('fa-moon');
            themeIcon.setAttribute('title', 'Switch to Dark Mode');
        } else {
            themeIcon.classList.remove('fa-moon');
            themeIcon.classList.add('fa-sun');
            themeIcon.setAttribute('title', 'Switch to Light Mode');
        }
    }
    
    // 2. File Upload Drag & Drop
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('email_file');
    const fileInfo = document.getElementById('file-info');
    const fileNameSpan = document.getElementById('file-name');
    const removeFileBtn = document.getElementById('remove-file');
    const manualInputForm = document.getElementById('manual-input-fields');
    
    if (uploadArea && fileInput) {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        // Highlight drop zone when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => uploadArea.classList.add('dragover'), false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, () => uploadArea.classList.remove('dragover'), false);
        });
        
        // Handle dropped files
        uploadArea.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length) {
                fileInput.files = files;
                handleFileSelection(files[0]);
            }
        });
        
        // Handle file browse selection
        fileInput.addEventListener('change', (e) => {
            if (fileInput.files.length) {
                handleFileSelection(fileInput.files[0]);
            }
        });
        
        // Remove file selection
        if (removeFileBtn) {
            removeFileBtn.addEventListener('click', (e) => {
                e.preventDefault();
                fileInput.value = '';
                fileInfo.classList.add('d-none');
                if (manualInputForm) {
                    manualInputForm.style.opacity = '1';
                    manualInputForm.style.pointerEvents = 'auto';
                }
            });
        }
    }
    
    function handleFileSelection(file) {
        const ext = file.name.split('.').pop().lowerCase || file.name.split('.').pop().toLowerCase();
        if (ext !== 'txt' && ext !== 'eml') {
            alert('Unsupported file format. Please upload .txt or .eml files only.');
            fileInput.value = '';
            fileInfo.classList.add('d-none');
            return;
        }
        
        fileNameSpan.textContent = `${file.name} (${formatBytes(file.size)})`;
        fileInfo.classList.remove('d-none');
        
        // Visual feedback: dim manual input since file takes precedence
        if (manualInputForm) {
            manualInputForm.style.opacity = '0.5';
            manualInputForm.style.pointerEvents = 'none';
        }
    }
    
    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
    
    // 3. Risk Bar Animation
    const riskBar = document.querySelector('.risk-progress-bar');
    if (riskBar) {
        const targetWidth = riskBar.getAttribute('data-value');
        setTimeout(() => {
            riskBar.style.width = `${targetWidth}%`;
        }, 150);
    }
});
