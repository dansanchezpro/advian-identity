// Login helper functions for Identity Server UI

window.debugLog = function(message) {
    console.log('[UI DEBUG]', message);
};

window.submitOidcForm = function(formData) {
    console.log('[UI] Submitting OIDC form to API:', formData);
    
    var form = document.createElement('form');
    form.method = 'post';
    form.action = 'https://localhost:5000/api/auth/oidc-form-login';
    form.style.display = 'none';
    
    // Add all form fields
    Object.keys(formData).forEach(function(key) {
        if (formData[key]) {
            var input = document.createElement('input');
            input.type = 'hidden';
            input.name = key;
            input.value = formData[key];
            form.appendChild(input);
        }
    });
    
    document.body.appendChild(form);
    form.submit();
};