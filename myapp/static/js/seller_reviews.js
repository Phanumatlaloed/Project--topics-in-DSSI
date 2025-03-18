document.addEventListener('DOMContentLoaded', function() {
    // Handle hamburger menu for mobile
    const hamburgerMenu = document.getElementById('hamburger-menu');
    const sidebar = document.getElementById('sidebar');
    
    if (hamburgerMenu && sidebar) {
        hamburgerMenu.addEventListener('click', function() {
            sidebar.classList.toggle('active');
            
            // Change hamburger to X when sidebar is open
            const bars = hamburgerMenu.querySelectorAll('.bar');
            bars.forEach(bar => bar.classList.toggle('active'));
        });
    }
    
    // Add smooth hover effect to sidebar menu items
    const menuItems = document.querySelectorAll('.menu-item a');
    menuItems.forEach(item => {
        item.addEventListener('mouseenter', function() {
            this.style.paddingLeft = '25px';
        });
        
        item.addEventListener('mouseleave', function() {
            this.style.paddingLeft = '20px';
        });
    });
    
    // Add image preview expansion
    const reviewImages = document.querySelectorAll('.img-thumbnail');
    reviewImages.forEach(img => {
        img.addEventListener('click', function() {
            // Create modal for image preview
            const modal = document.createElement('div');
            modal.classList.add('image-preview-modal');
            
            const modalImg = document.createElement('img');
            modalImg.src = this.src;
            
            const closeBtn = document.createElement('span');
            closeBtn.innerHTML = '&times;';
            closeBtn.classList.add('close-modal');
            
            modal.appendChild(closeBtn);
            modal.appendChild(modalImg);
            document.body.appendChild(modal);
            
            // Show the modal with animation
            setTimeout(() => {
                modal.style.opacity = '1';
            }, 10);
            
            // Close modal when clicking the close button or outside the image
            closeBtn.addEventListener('click', closeModal);
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    closeModal();
                }
            });
            
            function closeModal() {
                modal.style.opacity = '0';
                setTimeout(() => {
                    document.body.removeChild(modal);
                }, 300);
            }
        });
    });
    
    // Add character counter for response textarea
    const responseTextareas = document.querySelectorAll('textarea[name="response_text"]');
    responseTextareas.forEach(textarea => {
        // Create character counter element
        const charCounter = document.createElement('div');
        charCounter.classList.add('char-counter');
        charCounter.textContent = '0/300 characters';
        
        // Add after textarea
        textarea.insertAdjacentElement('afterend', charCounter);
        
        // Update character count when typing
        textarea.addEventListener('input', function() {
            const count = this.value.length;
            charCounter.textContent = `${count}/300 characters`;
            
            // Change color when approaching limit
            if (count > 250) {
                charCounter.style.color = '#ff5252';
            } else {
                charCounter.style.color = '#666';
            }
        });
    });
    
    // Form validation
    const forms = document.querySelectorAll('.response-form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const textarea = this.querySelector('textarea');
            if (textarea.value.trim().length < 10) {
                e.preventDefault();
                
                // Show validation error
                const errorMsg = document.createElement('div');
                errorMsg.classList.add('validation-error');
                errorMsg.textContent = 'Response must be at least 10 characters long';
                
                // Remove existing error message if any
                const existingError = this.querySelector('.validation-error');
                if (existingError) {
                    existingError.remove();
                }
                
                textarea.insertAdjacentElement('afterend', errorMsg);
                textarea.focus();
                
                // Add error styling
                textarea.classList.add('error');
                
                // Remove error styling when typing again
                textarea.addEventListener('input', function() {
                    this.classList.remove('error');
                    const error = form.querySelector('.validation-error');
                    if (error) {
                        error.remove();
                    }
                });
            }
        });
    });
    
    // Add sparkle effect to buttons
    const buttons = document.querySelectorAll('.btn-submit');
    buttons.forEach(btn => {
        btn.addEventListener('mousemove', function(e) {
            const x = e.pageX - this.offsetLeft;
            const y = e.pageY - this.offsetTop;
            
            this.style.setProperty('--x', x + 'px');
            this.style.setProperty('--y', y + 'px');
        });
    });
    
    // Add tooltip for ratings
    const ratings = document.querySelectorAll('.rating');
    ratings.forEach(rating => {
        const stars = parseInt(rating.textContent.match(/\d+/)[0]);
        let tooltip = '';
        
        if (stars === 5) tooltip = 'Excellent!';
        else if (stars === 4) tooltip = 'Very Good';
        else if (stars === 3) tooltip = 'Average';
        else if (stars === 2) tooltip = 'Below Average';
        else tooltip = 'Poor';
        
        rating.setAttribute('title', tooltip);
        rating.style.cursor = 'help';
    });
    
    // Add greeting message
    const currentHour = new Date().getHours();
    let greeting = '';
    
    if (currentHour < 12) greeting = 'Good Morning';
    else if (currentHour < 18) greeting = 'Good Afternoon';
    else greeting = 'Good Evening';
    
    const container = document.querySelector('.container h2');
    if (container) {
        const originalText = container.textContent;
        container.innerHTML = `${greeting}! <br>${originalText}`;
    }
});
