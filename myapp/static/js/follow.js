// ในไฟล์ static/js/follow.js
document.addEventListener('DOMContentLoaded', function() {
    const followForms = document.querySelectorAll('.follow-form');
    
    followForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const userId = this.querySelector('.follow-btn').dataset.userId;
            const csrfToken = this.querySelector('[name="csrfmiddlewaretoken"]').value;
            
            fetch(this.action, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': csrfToken
                },
                body: new URLSearchParams({
                    'csrfmiddlewaretoken': csrfToken
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // อัพเดททุกปุ่มที่เกี่ยวข้องกับผู้ใช้คนนี้
                    const allButtons = document.querySelectorAll(`.follow-btn[data-user-id="${userId}"]`);
                    
                    allButtons.forEach(button => {
                        if (data.is_following) {
                            button.classList.remove('btn-outline-primary');
                            button.classList.add('btn-danger');
                            button.textContent = 'ติดตามแล้ว';
                        } else {
                            button.classList.remove('btn-danger');
                            button.classList.add('btn-outline-primary');
                            button.textContent = 'ติดตาม';
                        }
                    });
                }
            })
            .catch(error => console.error('Error:', error));
        });
    });
});